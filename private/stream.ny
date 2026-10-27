/** @brief Caller-driven TCP/TLS state machine using only net_core product APIs. */
part of TlsEngine;

enum TlsStreamOperation { Idle, Handshake, Read, Write, Shutdown }
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
pub struct TlsStream { cell: arc<TlsStreamState>?; }

func tls_stream_error(kind: TlsErrorKind) -> TlsStreamError { return TlsStreamError{tls_error: TlsError{kind: kind}}; }
func tls_stream_transport_error(error: ref NetError) -> TlsStreamError {
  if error.kind == NetErrorKind.Cancelled { return tls_stream_error(TlsErrorKind.Cancelled); }
  if error.kind == NetErrorKind.TimedOut { return tls_stream_error(TlsErrorKind.TimedOut); }
  return TlsStreamError{transport_error: error};
}
func tls_stream_retire(cell: arc<TlsStreamState>) -> void {
  var state: arc<TlsStreamState> = cell;
  state.closed = true;
  state.driver.Close();
  state.connection.Close();
  state.session.Close();
  state.incoming_start = 0 as intptr; state.incoming_count = 0 as intptr;
  state.outgoing_start = 0 as intptr; state.outgoing_count = 0 as intptr;
}
func tls_stream_finish(cell: arc<TlsStreamState>, error: TlsStreamError?, retire: bool) -> int32 {
  var state: arc<TlsStreamState> = cell;
  let active: bool = state.operation != TlsStreamOperation.Idle;
  var promise: AsyncPromise<TlsTransfer> = state.promise;
  let value: TlsTransfer = TlsTransfer{bytes_transferred: state.progress, buffer: state.result_buffer, eof: state.operation_eof, error: error};
  if retire { tls_stream_retire(state); }
  state.operation = TlsStreamOperation.Idle;
  state.wait = nil;
  state.input = NetBuffer{}; state.result_buffer = NetBuffer{};
  state.retained = 0 as intptr; state.progress = 0 as intptr;
  state.operation_done = false; state.operation_eof = false;
  state.promise = AsyncPromise<TlsTransfer>{};
  state.options = NetOperationOptions{};
  state.driving = false;
  // No state mutation follows publication: continuations may Close, move, enqueue or Poll.
  if active { promise.Complete(value); return 1; }
  return 0;
}
func tls_stream_fail(cell: arc<TlsStreamState>, error: ref TlsStreamError) -> int32 {
  return tls_stream_finish(cell, error, true);
}
func tls_stream_control(cell: arc<TlsStreamState>) -> TlsStreamError? {
  var state: arc<TlsStreamState> = cell;
  let checked: Result<Unit, NetError> = state.options.Check(NetClock.NowNanoseconds());
  let error: NetError? = checked.get_if<NetError>();
  if error != nil { return tls_stream_transport_error(error as NetError); }
  return nil;
}
func tls_stream_register(cell: arc<TlsStreamState>, writable: bool) -> TlsStreamError? {
  var state: arc<TlsStreamState> = cell;
  var queued: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = NetError{kind: NetErrorKind.System};
  if writable { queued = state.connection.WhenWritable(state.driver, state.options); }
  else { queued = state.connection.WhenReadable(state.driver, state.options); }
  let error: NetError? = queued.get_if<NetError>();
  if error != nil { return tls_stream_transport_error(error as NetError); }
  state.wait = (queued.get_if<AsyncFuture<Result<Unit, NetError>>>()) as AsyncFuture<Result<Unit, NetError>>;
  return nil;
}
func tls_stream_admit(cell: arc<TlsStreamState>, operation: TlsStreamOperation, options: ref NetOperationOptions, cost: intptr) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  var state: arc<TlsStreamState> = cell;
  if state.closed { return tls_stream_error(TlsErrorKind.Closed); }
  if state.driving || state.operation != TlsStreamOperation.Idle { return tls_stream_error(TlsErrorKind.InvalidState); }
  if operation != TlsStreamOperation.Handshake && !state.handshaken { return tls_stream_error(TlsErrorKind.InvalidState); }
  if operation == TlsStreamOperation.Write && state.peer_closed { return tls_stream_error(TlsErrorKind.InvalidState); }
  if cost > state.maximum { return tls_stream_error(TlsErrorKind.ResourceExhausted); }
  let checked: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  let failure: NetError? = checked.get_if<NetError>();
  if failure != nil { return tls_stream_transport_error(failure as NetError); }
  var promise: AsyncPromise<TlsTransfer> = AsyncPromise<TlsTransfer>.New();
  state.promise = promise; state.operation = operation; state.options = options;
  state.retained = cost; state.progress = 0 as intptr;
  state.operation_done = false; state.operation_eof = false;
  return promise.FutureHandle();
}
/** @brief Move one shared private state owner, invalidating the public source. */
pub method(TlsStream) operator move() -> TlsStream {
  let cell: arc<TlsStreamState>? = self.cell; self.cell = nil;
  return TlsStream{cell: cell};
}
/** @brief Retire outstanding work on stream destruction. */
pub method(TlsStream) operator drop() -> void { self.Close(); }
/** @brief Construct with the default one MiB pending-payload limit. */
pub static method(TlsStream) NewClient(connection: ref mut TcpConnection, config: ref TlsClientConfig) -> Result<TlsStream, TlsStreamError> {
  return TlsStream.NewClientWithLimit(connection, config, 1048576 as intptr);
}
/** @brief Build TLS/driver first and transfer the TCP owner only after successful construction. */
pub static method(TlsStream) NewClientWithLimit(connection: ref mut TcpConnection, config: ref TlsClientConfig, max_retained_bytes: intptr) -> Result<TlsStream, TlsStreamError> {
  if max_retained_bytes < (0 as intptr) { return tls_stream_error(TlsErrorKind.InvalidArgument); }
  if !connection.IsOpen() { return tls_stream_error(TlsErrorKind.Closed); }
  var made: Result<TlsSession, TlsError> = TlsSession.NewClient(config);
  let failure: TlsError? = made.get_if<TlsError>();
  if failure != nil { return TlsStreamError{tls_error: failure}; }
  var driver_result: Result<NetEventLoop, NetError> = NetEventLoop.New(1);
  let driver_error: NetError? = driver_result.get_if<NetError>();
  if driver_error != nil { return tls_stream_transport_error(driver_error as NetError); }
  let state: arc<TlsStreamState> = new arc<TlsStreamState>{
    connection: move(connection), session: move((made.get_if<TlsSession>()) as TlsSession),
    driver: move((driver_result.get_if<NetEventLoop>()) as NetEventLoop), maximum: max_retained_bytes
  };
  return TlsStream{cell: state};
}
/** @brief Queue a verified handshake without doing socket work during admission. */
pub method(TlsStream) HandshakeAsync(options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return tls_stream_error(TlsErrorKind.Closed); }
  return tls_stream_admit(optional as arc<TlsStreamState>, TlsStreamOperation.Handshake, options, 0 as intptr);
}
/** @brief Reserve bounded plaintext storage for one partial read. */
pub method(TlsStream) ReadAsync(max_bytes: int32, options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  if max_bytes < 0 || max_bytes > 16384 { return tls_stream_error(TlsErrorKind.InvalidArgument); }
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return tls_stream_error(TlsErrorKind.Closed); }
  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = tls_stream_admit(state, TlsStreamOperation.Read, options, max_bytes as intptr);
  if admitted.IsOk() { state.read_capacity = max_bytes; }
  return admitted;
}
/** @brief Retain immutable backing and send from a persistent plaintext offset. */
pub method(TlsStream) WriteAllAsync(buffer: ref NetBuffer, options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return tls_stream_error(TlsErrorKind.Closed); }
  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  let admitted: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = tls_stream_admit(state, TlsStreamOperation.Write, options, buffer.RetainedBytes());
  if admitted.IsOk() { state.input = buffer; }
  return admitted;
}
/** @brief Queue orderly protocol shutdown using the unchanged operation controls. */
pub method(TlsStream) ShutdownAsync(options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return tls_stream_error(TlsErrorKind.Closed); }
  return tls_stream_admit(optional as arc<TlsStreamState>, TlsStreamOperation.Shutdown, options, 0 as intptr);
}
/** @brief Report at most one pending operation. */
pub method(TlsStream) PendingCount() -> int32 {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return 0; }
  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.operation == TlsStreamOperation.Idle { return 0; }
  return 1;
}
/** @brief Report pending payload charge only. */
pub method(TlsStream) RetainedBytes() -> intptr {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return 0 as intptr; }
  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  return state.retained;
}
/** @brief Copy negotiated ALPN without exposing engine state. */
pub method(TlsStream) SelectedAlpn() -> Result<string, TlsStreamError> {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return tls_stream_error(TlsErrorKind.Closed); }
  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.closed { return tls_stream_error(TlsErrorKind.Closed); }
  let selected: Result<string, TlsError> = state.session.SelectedAlpn();
  let error: TlsError? = selected.get_if<TlsError>();
  if error != nil { return TlsStreamError{tls_error: error}; }
  return (selected.get_if<string>()) as string;
}
/** @brief Query local ownership rather than remote connection health. */
pub method(TlsStream) IsOpen() -> bool {
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return false; }
  let state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  return !state.closed;
}
/** @brief Detach the owner and retire native resources before invoking a pending continuation. */
pub method(TlsStream) Close() -> void {
  let optional: arc<TlsStreamState>? = self.cell;
  self.cell = nil;
  if optional == nil { return; }
  tls_stream_finish(optional as arc<TlsStreamState>, tls_stream_error(TlsErrorKind.Closed), true);
}
