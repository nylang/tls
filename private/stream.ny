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

static method(TlsStreamError) FromTlsKind(kind: TlsErrorKind) -> TlsStreamError {
  return TlsStreamError{tls_error: TlsError{kind: kind}};
}

static method(TlsStreamError) FromTransport(error: ref NetError) -> TlsStreamError {
  if error.kind == NetErrorKind.Cancelled {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Cancelled);
  }

  if error.kind == NetErrorKind.TimedOut {
    return TlsStreamError.FromTlsKind(TlsErrorKind.TimedOut);
  }

  return TlsStreamError{transport_error: error};
}

// Retire transport and provider state together before publishing a terminal operation result.
method(TlsStreamState) Retire() -> void {
  self.closed = true;
  self.driver.Close();
  self.connection.Close();
  self.session.Close();
  self.incoming_start = 0ip;
  self.incoming_count = 0ip;
  self.outgoing_start = 0ip;
  self.outgoing_count = 0ip;
}

// Detach the current operation before completing its promise so reentrant callbacks observe the retired operation.
method(TlsStreamState) Finish(error: TlsStreamError?, retire: bool) -> int32 {
  let active: bool = self.operation != TlsStreamOperation.Idle;
  var promise: AsyncPromise<TlsTransfer> = self.promise;
  let value: TlsTransfer = TlsTransfer{
    bytes_transferred: self.progress,
    buffer: self.result_buffer,
    eof: self.operation_eof,
    error: error
  };
  if retire {
    self.Retire();
  }

  self.operation = TlsStreamOperation.Idle;
  self.wait = nil;
  self.input = NetBuffer{};
  self.result_buffer = NetBuffer{};
  self.retained = 0ip;
  self.progress = 0ip;
  self.operation_done = false;
  self.operation_eof = false;
  self.promise = AsyncPromise<TlsTransfer>{};
  self.options = NetOperationOptions{};
  self.driving = false;
  // No state mutation follows publication: continuations may Close, move, enqueue or Poll.
  if active {
    promise.Complete(value);

    return 1;
  }

  return 0;
}

method(TlsStreamState) Fail(error: ref TlsStreamError) -> int32 {
  return self.Finish(error, true);
}

method(TlsStreamState) ControlError() -> TlsStreamError? {
  let checked: Result<Unit, NetError> = self.options.CheckNow();
  let error: NetError? = checked.get_if<NetError>();
  if error != nil {
    return TlsStreamError.FromTransport(error as NetError);
  }

  return nil;
}

method(TlsStreamState) RegisterReadiness(writable: bool) -> TlsStreamError? {
  var queued: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = NetError{kind: NetErrorKind.System};
  if writable {
    queued = self.connection.WhenWritable(self.driver, self.options);
  } else {
    queued = self.connection.WhenReadable(self.driver, self.options);
  }

  let error: NetError? = queued.get_if<NetError>();
  if error != nil {
    return TlsStreamError.FromTransport(error as NetError);
  }

  self.wait = (queued.get_if<AsyncFuture<Result<Unit, NetError>>>()) as AsyncFuture<Result<Unit, NetError>>;

  return nil;
}

// Check shared session state and original controls before reserving storage for a new operation.
method(TlsStreamState) Admit(
  operation: TlsStreamOperation,
  options: ref NetOperationOptions,
  cost: intptr
) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  if self.closed {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  if self.driving || self.operation != TlsStreamOperation.Idle {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if operation != TlsStreamOperation.Handshake && !self.handshaken {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if operation == TlsStreamOperation.Write && self.peer_closed {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if cost > self.maximum {
    return TlsStreamError.FromTlsKind(TlsErrorKind.ResourceExhausted);
  }

  let checked: Result<Unit, NetError> = options.CheckNow();
  let failure: NetError? = checked.get_if<NetError>();
  if failure != nil {
    return TlsStreamError.FromTransport(failure as NetError);
  }

  var promise: AsyncPromise<TlsTransfer> = AsyncPromise<TlsTransfer>.New();
  self.promise = promise;
  self.operation = operation;
  self.options = options;
  self.retained = cost;
  self.progress = 0ip;
  self.operation_done = false;
  self.operation_eof = false;

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
  return TlsStream.NewClientWithLimit(connection, config, 1048576ip);
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
  if max_retained_bytes <(0ip) {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidArgument);
  }

  if !connection.IsOpen() {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var made: Result<TlsSession, TlsError> = TlsSession.NewClient(config);
  let failure: TlsError? = made.get_if<TlsError>();
  if failure != nil {
    return TlsStreamError{tls_error: failure};
  }

  var driver_result: Result<NetEventLoop, NetError> = NetEventLoop.New(1);
  let driver_error: NetError? = driver_result.get_if<NetError>();
  if driver_error != nil {
    return TlsStreamError.FromTransport(driver_error as NetError);
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
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  return (optional as arc<TlsStreamState>).Admit(TlsStreamOperation.Handshake,
    options,
    0ip);
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
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidArgument);
  }

  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = (state).Admit(TlsStreamOperation.Read,
    options,
    max_bytes as intptr);
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
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = (state).Admit(TlsStreamOperation.Write,
    options,
    buffer.RetainedBytes());
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
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  return (optional as arc<TlsStreamState>).Admit(TlsStreamOperation.Shutdown, options, 0ip);
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
    return 0ip;
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
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.closed {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
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

  (optional as arc<TlsStreamState>).Finish(TlsStreamError.FromTlsKind(TlsErrorKind.Closed), true);
}
