/** @brief Deterministic cancellation, deadline and Close interleavings at transport boundaries. */
part of TlsEngine;

@extern("C") func nyra_tls_test_boundary_arm(direction: int32) -> void;
@extern("C") func nyra_tls_test_boundary_wait() -> int32;
@extern("C") func nyra_tls_test_boundary_release() -> void;
@extern("C") func nyra_tls_test_boundary_hit() -> int32;

func tls_stream_test_retired(stream: ref TlsStream) -> void {
  tls_test_assert(!stream.IsOpen() && stream.PendingCount() == 0 && stream.RetainedBytes() == 0, "completion observes retired owners and detached payload");
}
func tls_stream_test_boundary_write(cancel: bool, expire: bool, native_failure: bool) -> void {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  var due: uint64 = NetClock.NowNanoseconds() + 10000000000u64;
  if expire { due = NetClock.NowNanoseconds() + 1000000000u64; }
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.At(due), cancellation: token};
  let payload: NetBuffer = tls_stream_test_payload(1);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(payload, options));
  if native_failure { nyra_tls_test_write_controls(0, 0, 0); nyra_tls_test_boundary_arm(2); }
  else { nyra_tls_test_boundary_arm(1); }
  var spawned: Result<Thread, ThreadError> = Thread.Spawn(lambda [copy token, copy due, copy cancel, copy expire] () -> void {
    let reached: int32 = nyra_tls_test_boundary_wait();
    if expire { while NetClock.NowNanoseconds() < due { Thread.Sleep(1u32); } }
    if cancel { token.Cancel(); }
    nyra_tls_test_boundary_release();
    tls_test_assert(reached == 1, "worker reaches final-write rendezvous");
  });
  tls_test_assert(spawned.IsOk(), "boundary control worker starts");
  var worker: Thread = move((spawned.get_if<Thread>()) as Thread);
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(worker.Join().IsOk() && nyra_tls_test_boundary_hit() == 1, "control is published before the native write returns");
  if native_failure { tls_test_assert(nyra_tls_test_written_bytes() == 0, "injected native failure sends no ciphertext"); }
  var expected: TlsErrorKind = TlsErrorKind.TimedOut;
  if cancel { expected = TlsErrorKind.Cancelled; }
  tls_stream_test_tls_error(result, expected);
  tls_test_assert(result.bytes_transferred == (1 as intptr) && !result.eof, "terminal final flush preserves the TLS-accepted plaintext count");
  tls_stream_test_retired(stream);
  stream.Close();
  tls_test_assert(stream.Poll(0).IsOk(), "retired Poll and Close remain idempotent");
  tls_test_assert(nyra_tls_test_server_join() == 0, "final-flush peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_cancel_during_final_flush() { tls_stream_test_boundary_write(true, false, false); }
@test(tag = "tls_engine")
func test_tls_stream_deadline_during_final_flush() { tls_stream_test_boundary_write(false, true, false); }
@test(tag = "tls_engine")
func test_tls_stream_cancel_precedes_deadline_during_final_flush() { tls_stream_test_boundary_write(true, true, false); }
@test(tag = "tls_engine")
func test_tls_stream_cancel_precedes_native_flush_error() { tls_stream_test_boundary_write(true, false, true); }

@test(tag = "tls_engine")
func test_tls_stream_cancel_after_native_read_before_plaintext() {
  var stream: TlsStream = tls_stream_test_new(2, 0);
  tls_stream_test_handshake(stream);
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64), cancellation: token};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ReadAsync(16, options));
  nyra_tls_test_boundary_arm(0);
  var spawned: Result<Thread, ThreadError> = Thread.Spawn(lambda [copy token] () -> void {
    let reached: int32 = nyra_tls_test_boundary_wait();
    token.Cancel(); nyra_tls_test_boundary_release();
    tls_test_assert(reached == 1, "worker reaches successful native-read rendezvous");
  });
  tls_test_assert(spawned.IsOk(), "read cancellation worker starts");
  var worker: Thread = move((spawned.get_if<Thread>()) as Thread);
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(worker.Join().IsOk() && nyra_tls_test_boundary_hit() == 1, "read cancellation precedes protocol processing");
  tls_stream_test_tls_error(result, TlsErrorKind.Cancelled);
  tls_test_assert(result.bytes_transferred == 0 && result.buffer.Len() == 0 && !result.eof, "cancelled encrypted input is not published as plaintext or EOF");
  tls_stream_test_retired(stream);
  tls_test_assert(nyra_tls_test_server_join() == 0, "read-boundary peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_shutdown_cancel_after_local_alert() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  nyra_tls_test_write_controls(0, 0, -1);
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64), cancellation: token};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ShutdownAsync(options));
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  let pointer: *mut TlsStream = &mut stream;
  future.RegisterContinuation(lambda [copy pointer, copy counter] () -> void {
    unsafe { tls_stream_test_retired(*pointer); (*pointer).Close(); }
    var value: arc<TlsStreamTestCounter> = counter; value.hits = value.hits + 1;
  });
  var rounds: int32 = 0;
  while nyra_tls_test_written_bytes() == 0 && !future.is_completed && rounds < 5000 {
    tls_test_assert(stream.Poll(0).IsOk(), "shutdown sends its local alert"); rounds = rounds + 1;
  }
  tls_test_assert(nyra_tls_test_written_bytes() > 0 && !future.is_completed, "local alert alone leaves shutdown awaiting the peer");
  token.Cancel();
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_stream_test_tls_error(result, TlsErrorKind.Cancelled);
  tls_test_assert(result.bytes_transferred == 0 && !result.eof && counter.hits == 1, "cancelled shutdown publishes one terminal result");
  stream.Close(); tls_test_assert(stream.Poll(0).IsOk() && counter.hits == 1, "repeated retirement cannot republish shutdown");
  tls_test_assert(nyra_tls_test_server_join() == 0, "cancelled shutdown peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_close_pending_write_after_cancel() {
  var stream: TlsStream = tls_stream_test_new(3, 0);
  tls_stream_test_handshake(stream);
  nyra_tls_test_write_controls(317, 5, -1);
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64), cancellation: token};
  let payload: NetBuffer = tls_stream_test_payload(200000);
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.WriteAllAsync(payload, options));
  var rounds: int32 = 0;
  while nyra_tls_test_written_bytes() < 20000 && !future.is_completed && rounds < 5000 {
    tls_test_assert(stream.Poll(0).IsOk(), "write commits a plaintext prefix before Close"); rounds = rounds + 1;
  }
  tls_test_assert(!future.is_completed && nyra_tls_test_written_bytes() >= 20000 && stream.RetainedBytes() > 0, "Close interrupts retained partial write");
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(lambda [copy pointer, copy counter] () -> void {
    unsafe {
      tls_stream_test_retired(*pointer); (*pointer).Close();
      tls_test_assert((*pointer).Poll(0).IsOk() && (*pointer).ReadAsync(1, tls_stream_test_options()).IsErr(), "Close callback cannot revive the connection");
    }
    var value: arc<TlsStreamTestCounter> = counter; value.hits = value.hits + 1;
  });
  token.Cancel(); stream.Close();
  tls_test_assert(future.is_completed && counter.hits == 1, "explicit Close completes before any further Poll");
  let result: TlsTransfer = (future.GetResult().get_if<TlsTransfer>()) as TlsTransfer;
  tls_stream_test_tls_error(result, TlsErrorKind.Closed);
  tls_test_assert(result.bytes_transferred > 0 && result.bytes_transferred < payload.Len(), "Close preserves accepted prefix without replay");
  stream.Close(); tls_test_assert(stream.Poll(0).IsOk() && counter.hits == 1, "later cancellation processing cannot rewrite Closed");
  tls_test_assert(nyra_tls_test_server_join() == 0, "closed partial-write peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_shutdown_callback_and_late_cancel() {
  var stream: TlsStream = tls_stream_test_new(0, 0);
  tls_stream_test_handshake(stream);
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.After(NetClock.NowNanoseconds(), 10000000000u64), cancellation: token};
  let future: AsyncFuture<TlsTransfer> = tls_stream_test_future(stream.ShutdownAsync(options));
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(lambda [copy pointer, copy counter, copy token] () -> void {
    unsafe {
      tls_stream_test_retired(*pointer);
      tls_test_assert((*pointer).Poll(0).IsOk() && (*pointer).ShutdownAsync(tls_stream_test_options()).IsErr(), "successful shutdown callback observes closed protocol ownership");
      (*pointer).Close();
    }
    token.Cancel();
    var value: arc<TlsStreamTestCounter> = counter; value.hits = value.hits + 1;
  });
  let result: TlsTransfer = tls_stream_test_pump(stream, future);
  tls_test_assert(result.error == nil && result.bytes_transferred == 0 && counter.hits == 1, "cancellation after publication cannot replace successful shutdown");
  tls_test_assert(stream.Poll(0).IsOk() && counter.hits == 1 && ((future.GetResult().get_if<TlsTransfer>()) as TlsTransfer).error == nil, "completed Future remains stable after callback Close and cancellation");
  tls_test_assert(nyra_tls_test_server_join() == 0, "successful shutdown peer observed both notifications");
}
