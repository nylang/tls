// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module TlsTransportDriver;
part "stream_poll.ny";
part "channel.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";
import "interface/stream.ni";
import "interface/channel.ni";
import "private/tls.ny";

/** @brief Caller-driven TCP/TLS state machine using only net_core product APIs. */

enum TlsStreamOperation {
  Idle,
  Handshake,
  Read,
  Write,
  Shutdown
}

struct TlsStreamState {
  connection: TcpConnection;
  session: TlsSession;
  driver: NetEventLoop;
  closed: bool;
  driving: bool;
  handshaken: bool;
  peer_closed: bool;
  input_eof: bool;
  input_ended: bool;
  operation: TlsStreamOperation;
  options: NetOperationOptions;
  promise: AsyncPromise<TlsTransfer>;
  wait: AsyncFuture<Result<Unit, NetError>>?;
  input: NetBuffer;
  result_buffer: NetBuffer;
  maximum: intptr;
  retained: intptr;
  progress: intptr;
  read_capacity: int32;
  operation_done: bool;
  operation_eof: bool;
  incoming: <uint8>[16384];
  outgoing: <uint8>[16384];
  plaintext: <uint8>[16384];
  incoming_start: intptr;
  incoming_count: intptr;
  outgoing_start: intptr;
  outgoing_count: intptr;
}

/**
 * @brief Sole owner of TCP, TLS and a one-registration readiness driver; no hidden worker.
 * @note All methods/Future access remain on the caller thread. Only a retained cancellation
 *   token's Cancel may run elsewhere. At most one operation is pending per stream.
 */
pub struct TlsStream {
  cell: arc<TlsStreamState>?;
}

func tls_stream_error(kind: TlsErrorKind) -> TlsStreamError {
  return TlsStreamError{tls_error: TlsError{kind: kind}};
}

func tls_stream_transport_error(error: ref NetError) -> TlsStreamError {
  if error.kind == NetErrorKind.Cancelled {
    return tls_stream_error(TlsErrorKind.Cancelled);
  }

  if error.kind == NetErrorKind.TimedOut {
    return tls_stream_error(TlsErrorKind.TimedOut);
  }

  return TlsStreamError{transport_error: error};
}

// Retire transport and provider state together before publishing a terminal operation result.
func tls_stream_retire(cell: arc<TlsStreamState>) -> void {
  var state: arc<TlsStreamState> = cell;
  state.closed = true;
  state.driver.Close();
  state.connection.Close();
  state.session.Close();
  state.incoming_start = 0 as intptr;
  state.incoming_count = 0 as intptr;
  state.outgoing_start = 0 as intptr;
  state.outgoing_count = 0 as intptr;
}

// Detach the current operation before completing its promise so reentrant callbacks observe the retired operation.
func tls_stream_finish(cell: arc<TlsStreamState>, error: TlsStreamError?, retire: bool) -> int32 {
  var state: arc<TlsStreamState> = cell;
  let active: bool = state.operation != TlsStreamOperation.Idle;
  var promise: AsyncPromise<TlsTransfer> = state.promise;
  let value: TlsTransfer = TlsTransfer{
    bytes_transferred: state.progress,
    buffer: state.result_buffer,
    eof: state.operation_eof,
    error: error
  };
  if retire {
    tls_stream_retire(state);
  }

  state.operation = TlsStreamOperation.Idle;
  state.wait = nil;
  state.input = NetBuffer{};
  state.result_buffer = NetBuffer{};
  state.retained = 0 as intptr;
  state.progress = 0 as intptr;
  state.operation_done = false;
  state.operation_eof = false;
  state.promise = AsyncPromise<TlsTransfer>{};
  state.options = NetOperationOptions{};
  state.driving = false;
  // No state mutation follows publication: continuations may Close, move, enqueue or Poll.
  if active {
    promise.Complete(value);

    return 1;
  }

  return 0;
}

func tls_stream_fail(cell: arc<TlsStreamState>, error: ref TlsStreamError) -> int32 {
  return tls_stream_finish(cell, error, true);
}

func tls_stream_control(cell: arc<TlsStreamState>) -> TlsStreamError? {
  var state: arc<TlsStreamState> = cell;
  let checked: Result<Unit, NetError> = state.options.Check(NetClock.NowNanoseconds());
  let error: NetError? = checked.get_if<NetError>();
  if error != nil {
    return tls_stream_transport_error(error as NetError);
  }

  return nil;
}

func tls_stream_register(cell: arc<TlsStreamState>, writable: bool) -> TlsStreamError? {
  var state: arc<TlsStreamState> = cell;
  var queued: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = NetError{kind: NetErrorKind.System};
  if writable {
    queued = state.connection.WhenWritable(state.driver, state.options);
  } else {
    queued = state.connection.WhenReadable(state.driver, state.options);
  }

  let error: NetError? = queued.get_if<NetError>();
  if error != nil {
    return tls_stream_transport_error(error as NetError);
  }

  state.wait = (queued.get_if<AsyncFuture<Result<Unit, NetError>>>()) as AsyncFuture<Result<Unit, NetError>>;

  return nil;
}

// Check shared session state and original controls before reserving storage for a new operation.
func tls_stream_admit(
  cell: arc<TlsStreamState>,
  operation: TlsStreamOperation,
  options: ref NetOperationOptions,
  cost: intptr
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  var state: arc<TlsStreamState> = cell;
  if state.closed {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  if state.driving || state.operation != TlsStreamOperation.Idle {
    return tls_stream_error(TlsErrorKind.InvalidState);
  }

  if operation != TlsStreamOperation.Handshake && !state.handshaken {
    return tls_stream_error(TlsErrorKind.InvalidState);
  }

  if operation == TlsStreamOperation.Write && state.peer_closed {
    return tls_stream_error(TlsErrorKind.InvalidState);
  }

  if cost > state.maximum {
    return tls_stream_error(TlsErrorKind.ResourceExhausted);
  }

  let checked: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  let failure: NetError? = checked.get_if<NetError>();
  if failure != nil {
    return tls_stream_transport_error(failure as NetError);
  }

  var promise: AsyncPromise<TlsTransfer> = AsyncPromise<TlsTransfer>.New();
  state.promise = promise;
  state.operation = operation;
  state.options = options;
  state.retained = cost;
  state.progress = 0 as intptr;
  state.operation_done = false;
  state.operation_eof = false;

  return promise.FutureHandle();
}

/**
 * @brief Transfer the stream and its pending operation without duplicating native ownership.
 * @returns The TlsStream value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(TlsStream) operator move() -> TlsStream {
  let cell: arc<TlsStreamState>? = self.cell;
  self.cell = nil;

  return TlsStream{cell: cell};
}

/** @brief Retire outstanding work on stream destruction. */
pub method(TlsStream) operator drop() -> void {
  self.Close();
}

/**
 * @brief Create a client stream with a 1 MiB pending-payload limit, then move connection on
 *   success.
 * @returns Stream or configuration/driver failure; on failure connection is untouched.
 * @note The connection must have no outstanding I/O/readiness registrations. No handshake starts
 *   until HandshakeAsync is admitted and Poll is called. Configuration is copied immediately.
 */
pub static method(TlsStream) NewClient(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig
) -> Result<TlsStream, TlsStreamError> {
  return TlsStream.NewClientWithLimit(connection, config, 1048576 as intptr);
}

/**
 * @brief Create with a nonnegative pending-payload limit; reads reserve requested bytes.
 * @param max_retained_bytes Writes charge the complete NetBuffer backing, even for a small
 *   slice.
 * @returns Ok with TlsStream on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note Fixed stream/BIO/Future overhead and consumer-held completed buffers are outside this
 *   limit. One operation is admitted at a time; budget rejection never changes the active
 *   operation.
 */
pub static method(TlsStream) NewClientWithLimit(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig,
  max_retained_bytes: intptr
) -> Result<TlsStream, TlsStreamError> {
  if max_retained_bytes <(0 as intptr) {
    return tls_stream_error(TlsErrorKind.InvalidArgument);
  }

  if !connection.IsOpen() {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  var made: Result<TlsSession, TlsError> = TlsSession.NewClient(config);
  let failure: TlsError? = made.get_if<TlsError>();
  if failure != nil {
    return TlsStreamError{tls_error: failure};
  }

  var driver_result: Result<NetEventLoop, NetError> = NetEventLoop.New(1);
  let driver_error: NetError? = driver_result.get_if<NetError>();
  if driver_error != nil {
    return tls_stream_transport_error(driver_error as NetError);
  }

  let state: arc<TlsStreamState> = new arc<TlsStreamState>{
    connection: move(connection),
    session: move((made.get_if<TlsSession>()) as TlsSession),
    driver: move((driver_result.get_if<NetEventLoop>()) as NetEventLoop),
    maximum: max_retained_bytes
  };

  return TlsStream{cell: state};
}

/**
 * @brief Enqueue verified handshake; completion also requires flushing all generated ciphertext.
 * @returns A Future on successful admission, or the documented immediate error; completion
 *   follows the operation contract above.
 */
pub method(TlsStream) HandshakeAsync(
  options: ref NetOperationOptions
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  return tls_stream_admit(
    optional as arc<TlsStreamState>,
    TlsStreamOperation.Handshake,
    options,
    0 as intptr
  );
}

/**
 * @brief Enqueue one partial plaintext read of 0..16384 bytes after handshake.
 * @returns Future with owned initialized bytes, authenticated EOF, or progress/error; no
 *   borrowed buffer.
 * @note Zero size is a no-op and does not mean EOF. Dropping the Future does not cancel the
 *   operation.
 */
pub method(TlsStream) ReadAsync(
  max_bytes: int32,
  options: ref NetOperationOptions
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  if max_bytes < 0 || max_bytes > 16384 {
    return tls_stream_error(TlsErrorKind.InvalidArgument);
  }

  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = tls_stream_admit(
    state,
    TlsStreamOperation.Read,
    options,
    max_bytes as intptr
  );
  if admitted.IsOk() {
    state.read_capacity = max_bytes;
  }

  return admitted;
}

/**
 * @brief Retain an immutable buffer and send all plaintext in stable 16 KiB TLS retry blocks.
 * @returns Future preserving TLS-accepted plaintext count on failure. Original buffer may drop
 *   immediately.
 * @note Admission/control errors before enqueue return the outer Result without retiring the
 *   stream. After enqueue, failure/cancellation/timeout retires TCP/TLS and completes the Future
 *   once.
 */
pub method(TlsStream) WriteAllAsync(
  buffer: ref NetBuffer,
  options: ref NetOperationOptions
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = tls_stream_admit(
    state,
    TlsStreamOperation.Write,
    options,
    buffer.RetainedBytes()
  );
  if admitted.IsOk() {
    state.input = buffer;
  }

  return admitted;
}

/**
 * @brief Enqueue bidirectional close_notify; success flushes output and retires TCP/TLS before
 *   publication.
 * @returns A Future on successful admission, or the documented immediate error; completion
 *   follows the operation contract above.
 * @note The same absolute deadline/cancellation covers the complete shutdown exchange.
 */
pub method(TlsStream) ShutdownAsync(
  options: ref NetOperationOptions
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  return tls_stream_admit(optional as arc<TlsStreamState>, TlsStreamOperation.Shutdown, options, 0 as intptr);
}

/**
 * @brief Zero or one pending operation; completed consumer-held Futures are excluded.
 * @returns Zero or one pending operation; completed consumer-held Futures are excluded.
 */
pub method(TlsStream) PendingCount() -> int32 {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return 0;
  }

  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.operation == TlsStreamOperation.Idle {
    return 0;
  }

  return 1;
}

/**
 * @brief Payload backing bytes charged to the pending operation, excluding fixed queue overhead.
 * @returns Payload backing bytes charged to the pending operation, excluding fixed queue
 *   overhead.
 */
pub method(TlsStream) RetainedBytes() -> intptr {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return 0 as intptr;
  }

  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;

  return state.retained;
}

/**
 * @brief Owned negotiated ALPN after handshake; not available after stream retirement.
 * @returns Ok with string on success; Err with TlsStreamError on the failure paths described
 *   above.
 */
pub method(TlsStream) SelectedAlpn() -> Result<string, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.closed {
    return tls_stream_error(TlsErrorKind.Closed);
  }

  let selected: Result<string, TlsError> = state.session.SelectedAlpn();
  let error: TlsError? = selected.get_if<TlsError>();
  if error != nil {
    return TlsStreamError{tls_error: error};
  }

  return (selected.get_if<string>()) as string;
}

/**
 * @brief Whether the stream owns a live transport/engine; not a peer-liveness probe.
 * @returns Whether the stream owns a live transport/engine; not a peer-liveness probe.
 */
pub method(TlsStream) IsOpen() -> bool {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return false;
  }

  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;

  return !state.closed;
}

/** @brief Detach the owner and retire native resources before invoking a pending continuation. */
pub method(TlsStream) Close() -> void {
  let optional: arc<TlsStreamState>? = self.cell;
  self.cell = nil;
  if optional == nil {
    return;
  }

  tls_stream_finish(optional as arc<TlsStreamState>, tls_stream_error(TlsErrorKind.Closed), true);
}
