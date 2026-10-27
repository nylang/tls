/** @brief Loopback TLS stream transfers, controls, ownership and native short-write faults. */
part of TlsEngine;

@extern("C") func nyra_tls_test_server_start(mode: int32, size: int32) -> int32;
@extern("C") func nyra_tls_test_server_join() -> int32;
@extern("C") func nyra_tls_test_write_controls(limit: int32, stalls: int32, fail: int32) -> void;
@extern("C") func nyra_tls_test_partial_writes() -> int32;
@extern("C") func nyra_tls_test_write_stalls() -> int32;
@extern("C") func nyra_tls_test_fd_count() -> int32;
@extern("C") func nyra_tls_test_reset_native_code() -> int32;

func tls_stream_test_options() -> NetOperationOptions {
  return NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64)};
}
func tls_stream_test_connection(mode: int32, size: int32) -> TcpConnection {
  let port: int32 = nyra_tls_test_server_start(mode, size);
  tls_test_assert(port > 0, "loopback fixture starts");
  let endpoint: NetEndpoint = (NetEndpoint.New(IpAddress.V4(127u8, 0u8, 0u8, 1u8), port).get_if<NetEndpoint>()) as NetEndpoint;
  var connected: Result<TcpConnection, NetError> = TcpConnection.Dial(endpoint, tls_stream_test_options());
  tls_test_assert(connected.IsOk(), "loopback TCP connects");
  return move((connected.get_if<TcpConnection>()) as TcpConnection);
}
func tls_stream_test_new(mode: int32, size: int32) -> TlsStream {
  var connection: TcpConnection = tls_stream_test_connection(mode, size);
  var made: Result<TlsStream, TlsStreamError> = TlsStream.NewClient(connection, tls_test_config());
  tls_test_assert(made.IsOk(), "TLS stream adopts TCP");
  tls_test_assert(!connection.IsOpen(), "successful construction transfers the socket owner");
  return move((made.get_if<TlsStream>()) as TlsStream);
}
func tls_stream_test_future(queued: Result<AsyncFuture<TlsTransfer>, TlsStreamError>) -> AsyncFuture<TlsTransfer> {
  tls_test_assert(queued.IsOk(), "TLS operation is admitted");
  return (queued.get_if<AsyncFuture<TlsTransfer>>()) as AsyncFuture<TlsTransfer>;
}
func tls_stream_test_pump(stream: ref mut TlsStream, future: ref AsyncFuture<TlsTransfer>) -> TlsTransfer {
  var count: int32 = 0;
  while !future.is_completed && count < 50000 {
    tls_test_assert(stream.Poll(-1).IsOk(), "TLS Poll succeeds");
    count = count + 1;
  }
  tls_test_assert(future.is_completed, "bounded TLS operation completes");
  let result: Result<TlsTransfer, AsyncError> = future.GetResult();
  tls_test_assert(result.IsOk(), "operation errors remain in the transfer payload");
  return (result.get_if<TlsTransfer>()) as TlsTransfer;
}
func tls_stream_test_handshake(stream: ref mut TlsStream) -> void {
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(result.error == nil && result.bytes_transferred == 0, "verified handshake flushes before completion");
  tls_test_assert(stream.PendingCount() == 0 && stream.RetainedBytes() == 0, "handshake detaches pending state");
}
func tls_stream_test_tls_error(value: ref TlsTransfer, expected: TlsErrorKind) -> void {
  tls_test_assert(value.error != nil, "transfer carries a failure");
  if value.error == nil { return; }
  let error: TlsStreamError = value.error as TlsStreamError;
  tls_test_assert(error.tls_error != nil && error.transport_error == nil, "TLS failures retain their named category");
  if error.tls_error != nil { tls_test_assert((error.tls_error as TlsError).kind == expected, "expected TLS failure kind"); }
}
func tls_stream_test_payload(size: int32) -> NetBuffer {
  var bytes: owned <uint8>[] = new <uint8>[size];
  var i: int32 = 0;
  while i < size { bytes[i] = (i % 251) as uint8; i = i + 1; }
  let view: NetBytes = (NetBytes.FromRaw(&bytes[0], size as intptr).get_if<NetBytes>()) as NetBytes;
  return (NetBuffer.CopyFrom(view).get_if<NetBuffer>()) as NetBuffer;
}

@test(tag = "tls_engine")
func test_tls_stream_patterned_short_writes_and_shutdown() {
  var stream: TlsStream = tls_stream_test_new(0, 200000);
  nyra_tls_test_write_controls(317, 5, -1);
  tls_stream_test_handshake(stream);
  var payload: NetBuffer = tls_stream_test_payload(200000);
  let sent: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(payload, tls_stream_test_options()));
  tls_test_assert(stream.RetainedBytes() == (200000 as intptr), "pending write charges its retained root");
  payload = NetBuffer{};
  let written: TlsTransfer = tls_stream_test_pump(stream, sent);
  tls_test_assert(written.error == nil && written.bytes_transferred == (200000 as intptr), "all plaintext accepted exactly once");
  tls_test_assert(nyra_tls_test_partial_writes() > 0 && nyra_tls_test_write_stalls() > 0, "fixture forced partial writes and WouldBlock");
  var total: int32 = 0;
  var correct: bool = true;
  while total < 200000 {
    let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(4096, tls_stream_test_options()));
    let read: TlsTransfer = tls_stream_test_pump(stream, future);
    tls_test_assert(read.error == nil && !read.eof && read.bytes_transferred > 0, "echo returns initialized plaintext");
    if read.error != nil || read.bytes_transferred == 0 { break; }
    let bytes: NetBytes = read.buffer.Bytes();
    var i: int32 = 0;
    unsafe { while i < bytes.Len() as int32 { if bytes.Data()[i] != ((total + i) % 251) as uint8 { correct = false; } i = i + 1; } }
    total = total + read.bytes_transferred as int32;
  }
  tls_test_assert(total == 200000 && correct, "fragmented echo preserves every byte without duplication");
  let eof_future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(1, tls_stream_test_options()));
  let eof: TlsTransfer = tls_stream_test_pump(stream, eof_future);
  tls_test_assert(eof.error == nil && eof.eof && eof.bytes_transferred == 0, "close_notify is authenticated EOF");
  let closed: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ShutdownAsync(tls_stream_test_options()));
  tls_test_assert(tls_stream_test_pump(stream, closed).error == nil, "bidirectional TLS shutdown succeeds");
  tls_test_assert(!stream.IsOpen() && stream.PendingCount() == 0 && stream.RetainedBytes() == 0, "shutdown retires resources before publication");
  tls_test_assert(nyra_tls_test_server_join() == 0, "peer observed matching transfer and close_notify");
}

@test(tag = "tls_engine")
func test_tls_stream_admission_budget_and_move() {
  var connection: TcpConnection = tls_stream_test_connection(3, 0);
  var invalid: TlsClientConfig = tls_test_config(); invalid.peer_name = "";
  tls_test_assert(TlsStream.NewClient(connection, invalid).IsErr() && connection.IsOpen(), "failed construction preserves caller socket");
  var made: Result<TlsStream, TlsStreamError> = TlsStream.NewClientWithLimit(connection, tls_test_config(), 8 as intptr);
  var stream: TlsStream = move((made.get_if<TlsStream>()) as TlsStream);
  tls_stream_test_handshake(stream);
  let root: NetBuffer = tls_stream_test_payload(16);
  let tiny: NetBuffer = (root.Slice(0 as intptr, 1 as intptr).get_if<NetBuffer>()) as NetBuffer;
  tls_test_assert(stream.WriteAllAsync(tiny, tls_stream_test_options()).IsErr(), "small slice still charges the whole backing allocation");
  tls_test_assert(stream.ReadAsync(9, tls_stream_test_options()).IsErr(), "read reservation respects payload budget");
  tls_test_assert(stream.ReadAsync(-1, tls_stream_test_options()).IsErr(), "negative read rejected");
  tls_test_assert(stream.ReadAsync(16385, tls_stream_test_options()).IsErr(), "oversize read rejected");
  tls_test_assert(stream.PendingCount() == 0 && stream.IsOpen(), "admission failures preserve idle stream");
  let read: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(8, tls_stream_test_options()));
  tls_test_assert(stream.ShutdownAsync(tls_stream_test_options()).IsErr(), "overlapping operation rejected");
  tls_test_assert(stream.RetainedBytes() == (8 as intptr), "original operation remains admitted");
  var moved: TlsStream = move(stream);
  tls_test_assert(moved.PendingCount() == 1, "move preserves pending operation");
  moved.Close(); moved.Close();
  tls_test_assert(read.is_completed, "Close publishes pending read failure");
  tls_stream_test_tls_error((read.GetResult().get_if<TlsTransfer>()) as TlsTransfer, TlsErrorKind.Closed);
  tls_test_assert(nyra_tls_test_server_join() == 0, "silent peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_handshake_absolute_deadline() {
  var stream: TlsStream = tls_stream_test_new(1, 0);
  let started: uint64 = NetClock.NowNanoseconds();
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(started, 30000000u64)};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(options));
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_stream_test_tls_error(result, TlsErrorKind.TimedOut);
  tls_test_assert(NetClock.NowNanoseconds() - started < 2000000000u64, "wait uses the original deadline instead of restarting its budget");
  tls_test_assert(!stream.IsOpen() && stream.PendingCount() == 0, "timeout closes all stream resources");
  tls_test_assert(nyra_tls_test_server_join() == 0, "silent peer retires after timeout");
}

@test(tag = "tls_engine")
func test_tls_stream_wakeable_cancel() {
  var stream: TlsStream = tls_stream_test_new(1, 0);
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 3000000000u64), cancellation: token};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(options));
  var spawned: Result<Thread, ThreadError> = Thread.Spawn(lambda [copy token] () -> void { Thread.Sleep(30u32); token.Cancel(); });
  tls_test_assert(spawned.IsOk(), "cancelling thread starts");
  var worker: Thread = move((spawned.get_if<Thread>()) as Thread);
  let started: uint64 = NetClock.NowNanoseconds();
  tls_stream_test_tls_error(tls_stream_test_pump(stream, future), TlsErrorKind.Cancelled);
  tls_test_assert(NetClock.NowNanoseconds() - started < 2000000000u64, "wakeable cancellation interrupts idle native wait");
  tls_test_assert(worker.Join().IsOk(), "cancelling thread joins");
  tls_test_assert(!stream.IsOpen() && stream.PendingCount() == 0, "cancellation retires stream before completion");
  tls_test_assert(nyra_tls_test_server_join() == 0, "cancelled peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_transport_failure_preserves_progress() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  nyra_tls_test_write_controls(317, 5, 20000);
  let payload: NetBuffer = tls_stream_test_payload(200000);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(payload, tls_stream_test_options()));
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(result.error != nil && result.bytes_transferred > 0 && result.bytes_transferred < payload.Len(), "terminal write retains committed plaintext prefix count");
  if result.error != nil {
    let error: TlsStreamError = result.error as TlsStreamError;
    tls_test_assert(error.tls_error == nil && error.transport_error != nil, "transport error remains discoverable");
    if error.transport_error != nil {
      let native: NetError = error.transport_error as NetError;
      tls_test_assert(native.kind == NetErrorKind.ConnectionReset && native.native_code == nyra_tls_test_reset_native_code(), "native transport category/code preserved");
    }
  }
  tls_test_assert(!stream.IsOpen() && stream.RetainedBytes() == 0, "failed send releases payload backing and native owners");
  tls_test_assert(nyra_tls_test_server_join() == 0, "peer retires after injected send failure");
}

struct TlsStreamTestCounter { hits: int32; }
@test(tag = "tls_engine")
func test_tls_stream_close_callback_observes_terminal_state() {
  var stream: TlsStream = tls_stream_test_new(1, 0);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  tls_test_assert(stream.Poll(0).IsOk(), "handshake starts");
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(lambda [copy pointer, copy counter] () -> void {
    unsafe {
      tls_test_assert(!(*pointer).IsOpen() && (*pointer).PendingCount() == 0 && (*pointer).RetainedBytes() == 0, "Close callbacks see detached state");
      (*pointer).Close();
      tls_test_assert((*pointer).Poll(0).IsOk(), "Close callback may reenter Poll");
    }
    var value: arc<TlsStreamTestCounter> = counter; value.hits = value.hits + 1;
  });
  stream.Close();
  tls_test_assert(future.is_completed && counter.hits == 1, "pending operation completes exactly once");
  tls_test_assert(nyra_tls_test_server_join() == 0, "closed peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_poll_callback_can_enqueue_and_close() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(lambda [copy pointer, copy counter] () -> void {
    unsafe {
      tls_test_assert((*pointer).PendingCount() == 0, "successful callback sees idle stream");
      let pending: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = (*pointer).ReadAsync(1, tls_stream_test_options());
      tls_test_assert(pending.IsOk(), "successful callback may enqueue another operation");
      tls_test_assert((*pointer).Poll(0).IsOk(), "successful callback may drive that operation");
      (*pointer).Close();
      if pending.IsOk() { tls_test_assert(((pending.get_if<AsyncFuture<TlsTransfer>>()) as AsyncFuture<TlsTransfer>).is_completed, "callback Close retires reentered work"); }
    }
    var value: arc<TlsStreamTestCounter> = counter; value.hits = value.hits + 1;
  });
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(result.error == nil && counter.hits == 1 && !stream.IsOpen(), "outer Poll preserves callback state changes");
  tls_test_assert(nyra_tls_test_server_join() == 0, "reentered peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_truncation_after_plaintext_prefix() {
  var stream: TlsStream = tls_stream_test_new(2, 0);
  tls_stream_test_handshake(stream);
  let read: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(16, tls_stream_test_options()));
  let prefix: TlsTransfer = tls_stream_test_pump(stream, read);
  tls_test_assert(prefix.error == nil && prefix.bytes_transferred == (6 as intptr), "plaintext prefix precedes unexpected EOF");
  let bytes: NetBytes = prefix.buffer.Bytes();
  tls_test_assert(string.ViewFrom(bytes.Data() as *const int8, bytes.Len() as int32).Equal("prefix"), "received prefix remains owned after retirement");
  let tail: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(16, tls_stream_test_options()));
  let result: TlsTransfer = tls_stream_test_pump(stream, tail);
  tls_stream_test_tls_error(result, TlsErrorKind.UnexpectedEof);
  tls_test_assert(!result.eof && !stream.IsOpen(), "raw FIN is never authenticated EOF");
  tls_test_assert(nyra_tls_test_server_join() == 0, "truncated peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_verification_failure_is_terminal() {
  var connection: TcpConnection = tls_stream_test_connection(5, 0);
  var config: TlsClientConfig = tls_test_config(); config.peer_name = "wrong.example";
  var made: Result<TlsStream, TlsStreamError> = TlsStream.NewClient(connection, config);
  var stream: TlsStream = move((made.get_if<TlsStream>()) as TlsStream);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  tls_stream_test_tls_error(tls_stream_test_pump(stream, future), TlsErrorKind.PeerNameMismatch);
  tls_test_assert(!stream.IsOpen() && stream.ReadAsync(1, tls_stream_test_options()).IsErr(), "failed verification never admits plaintext I/O");
  tls_test_assert(nyra_tls_test_server_join() == 0, "verification-rejected peer retires");
}

func tls_stream_test_drop_round() -> void {
  var stream: TlsStream = tls_stream_test_new(1, 0);
  let ignored: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  tls_test_assert(stream.Poll(0).IsOk(), "drop test registers native work");
  tls_test_assert(!ignored.is_completed && stream.PendingCount() == 1, "operation remains pending before owner drop");
}

@test(tag = "tls_engine")
func test_tls_stream_drop_and_descriptor_recovery() {
  let baseline: int32 = nyra_tls_test_fd_count();
  var i: int32 = 0;
  while i < 64 {
    tls_stream_test_drop_round();
    tls_test_assert(nyra_tls_test_server_join() == 0, "abandoned peer joins");
    tls_test_assert(nyra_tls_test_fd_count() == baseline, "stream drop restores descriptor baseline");
    i = i + 1;
  }
}

@extern("C") func nyra_tls_test_written_bytes() -> int32;
@test(tag = "tls_engine")
func test_tls_stream_cancel_preserves_plaintext_prefix() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  nyra_tls_test_write_controls(317, 5, -1);
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64), cancellation: token};
  let payload: NetBuffer = tls_stream_test_payload(200000);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(payload, options));
  var rounds: int32 = 0;
  while nyra_tls_test_written_bytes() < 20000 && !future.is_completed && rounds < 5000 {
    tls_test_assert(stream.Poll(0).IsOk(), "write advances a committed prefix"); rounds = rounds + 1;
  }
  tls_test_assert(nyra_tls_test_written_bytes() >= 20000 && !future.is_completed, "cancel occurs during a partial later TLS record");
  token.Cancel();
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_stream_test_tls_error(result, TlsErrorKind.Cancelled);
  tls_test_assert(result.bytes_transferred > 0 && result.bytes_transferred < payload.Len(), "cancel preserves already TLS-accepted plaintext progress");
  tls_test_assert(!stream.IsOpen() && stream.RetainedBytes() == 0 && stream.PendingCount() == 0, "cancel releases retained input and partial ciphertext");
  tls_test_assert(nyra_tls_test_server_join() == 0, "peer retires after partial-write cancellation");
}

@test(tag = "tls_engine")
func test_tls_stream_read_deadline() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 20000000u64)};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(8, options));
  tls_stream_test_tls_error(tls_stream_test_pump(stream, future), TlsErrorKind.TimedOut);
  tls_test_assert(!stream.IsOpen() && stream.PendingCount() == 0 && stream.RetainedBytes() == 0, "read timeout retires its native wait and payload reservation");
  tls_test_assert(nyra_tls_test_server_join() == 0, "read-timeout peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_shutdown_deadline() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 20000000u64)};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ShutdownAsync(options));
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_stream_test_tls_error(result, TlsErrorKind.TimedOut);
  tls_test_assert(!result.eof && !stream.IsOpen() && stream.PendingCount() == 0, "sending close_notify does not turn an unacknowledged shutdown into success");
  tls_test_assert(nyra_tls_test_server_join() == 0, "shutdown-timeout peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_admission_controls_and_empty_io() {
  var connection: TcpConnection = tls_stream_test_connection(3, 0);
  var made: Result<TlsStream, TlsStreamError> = TlsStream.NewClientWithLimit(connection, tls_test_config(), 0 as intptr);
  var stream: TlsStream = move((made.get_if<TlsStream>()) as TlsStream);
  let token: NetCancellation = NetCancellation.New(); token.Cancel();
  let expired: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.At(0u64), cancellation: token};
  let rejected: Result<AsyncFuture<TlsTransfer>, TlsStreamError> = stream.HandshakeAsync(expired);
  tls_test_assert(rejected.IsErr() && stream.IsOpen() && stream.PendingCount() == 0, "pre-admission controls preserve the idle owner");
  if rejected.IsErr() {
    let error: TlsStreamError = (rejected.get_if<TlsStreamError>()) as TlsStreamError;
    tls_test_assert(error.tls_error != nil, "pre-admission cancellation is a named TLS control failure");
    if error.tls_error != nil { tls_test_assert((error.tls_error as TlsError).kind == TlsErrorKind.Cancelled, "cancellation precedes already-expired deadline at admission"); }
  }
  tls_test_assert(stream.ReadAsync(0, tls_stream_test_options()).IsErr(), "plaintext API requires verified handshake even for empty reads");
  tls_test_assert(stream.Poll(-2).IsErr() && stream.Poll(0).IsOk(), "invalid wait rejected and idle Poll remains usable");
  tls_stream_test_handshake(stream);
  let read: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(0, tls_stream_test_options()));
  let empty_read: TlsTransfer = tls_stream_test_pump(stream, read);
  tls_test_assert(empty_read.error == nil && !empty_read.eof && empty_read.buffer.Len() == 0, "empty read is not EOF");
  let write: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(NetBuffer{}, tls_stream_test_options()));
  let empty_write: TlsTransfer = tls_stream_test_pump(stream, write);
  tls_test_assert(empty_write.error == nil && empty_write.bytes_transferred == 0, "empty write fits a zero-byte payload budget");
  tls_test_assert(stream.ReadAsync(1, tls_stream_test_options()).IsErr(), "nonempty read exceeds zero-byte budget");
  stream.Close();
  tls_test_assert(nyra_tls_test_server_join() == 0, "zero-payload peer retires");
}

func tls_stream_test_drop_future(stream: ref mut TlsStream) -> void {
  let dropped: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.HandshakeAsync(tls_stream_test_options()));
  tls_test_assert(!dropped.is_completed, "new operation waits for explicit Poll");
}
@test(tag = "tls_engine")
func test_tls_stream_future_drop_does_not_cancel() {
  var stream: TlsStream = tls_stream_test_new(1, 0);
  tls_stream_test_drop_future(stream);
  tls_test_assert(stream.PendingCount() == 1 && stream.IsOpen(), "stream owns the pending operation after Future drop");
  tls_test_assert(stream.Poll(0).IsOk() && stream.PendingCount() == 1, "dropped Future does not stop protocol progress");
  stream.Close();
  tls_test_assert(nyra_tls_test_server_join() == 0, "unobserved operation retires on stream Close");
}
