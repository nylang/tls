// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of TlsContractTests;

/** @brief Deterministic cancellation, deadline and Close interleavings at transport boundaries. */

@extern("C") func nyra_tls_test_boundary_arm(direction: int32) -> void;

@extern("C") func nyra_tls_test_boundary_wait() -> int32;

@extern("C") func nyra_tls_test_boundary_release() -> void;

@extern("C") func nyra_tls_test_boundary_hit() -> int32;

method(TlsStream) TestRetired() -> void {
  AssertTrueMsg(
    !self.IsOpen() && self.PendingCount() == 0 && self.RetainedBytes() == 0,
    "completion observes retired owners and detached payload"
  );
}

struct TlsBoundaryWriteCase {
  cancel: bool;
  expire: bool;
  native_failure: bool;
}

method(TlsBoundaryWriteCase) Run() -> void {
  let cancel: bool = self.cancel;
  let expire: bool = self.expire;
  let native_failure: bool = self.native_failure;

  var stream: TlsStream = TlsStream.TestNew(3, 0);
  (stream).TestHandshake();
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  var due: uint64 = Instant.Now().ToDurationSinceEpochish().ToNanoseconds() + 10000000000u64;
  if expire {
    due = Instant.Now().ToDurationSinceEpochish().ToNanoseconds() + 1000000000u64;
  }

  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.At(due), cancellation: token};
  let payload: NetBuffer = NetBuffer.TlsTestPattern(1);
  let future: AsyncFuture<TlsTransfer> = AsyncFuture<TlsTransfer>.TlsTestAdmit(stream.WriteAllAsync(payload, options));
  if native_failure {
    nyra_tls_test_write_controls(0, 0, 0);
    nyra_tls_test_boundary_arm(2);
  } else {
    nyra_tls_test_boundary_arm(1);
  }

  var spawned: Result<Thread, ThreadError> = Thread.Spawn(
    lambda[copy token, copy due, copy cancel, copy expire]() -> void {
      let reached: int32 = nyra_tls_test_boundary_wait();
      if expire {
        while Instant.Now().ToDurationSinceEpochish().ToNanoseconds() < due {
          Thread.Sleep(1u32);
        }
      }

      if cancel {
        token.Cancel();
      }

      nyra_tls_test_boundary_release();
      AssertTrueMsg(reached == 1, "worker reaches final-write rendezvous");
    }
  );

  AssertTrueMsg(spawned.IsOk(), "boundary control worker starts");
  var worker: Thread = move((spawned.get_if<Thread>()) as Thread);
  let result: TlsTransfer = (stream).TestPump(future);
  AssertTrueMsg(
    worker.Join().IsOk() && nyra_tls_test_boundary_hit() == 1,
    "control is published before the native write returns"
  );
  if native_failure {
    AssertTrueMsg(nyra_tls_test_written_bytes() == 0, "injected native failure sends no ciphertext");
  }

  var expected: TlsErrorKind = TlsErrorKind.TimedOut;
  if cancel {
    expected = TlsErrorKind.Cancelled;
  }

  (result).TestTlsError(expected);
  AssertTrueMsg(
    result.bytes_transferred == (1 as intptr) && !result.eof,
    "terminal final flush preserves the TLS-accepted plaintext count"
  );
  (stream).TestRetired();
  stream.Close();
  AssertTrueMsg(stream.Poll(0).IsOk(), "retired Poll and Close remain idempotent");
  AssertTrueMsg(nyra_tls_test_server_join() == 0, "final-flush peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_cancel_during_final_flush() {
  TlsBoundaryWriteCase{cancel: true, expire: false, native_failure: false}.Run();
}

@test(tag = "tls_engine")
func test_tls_stream_deadline_during_final_flush() {
  TlsBoundaryWriteCase{cancel: false, expire: true, native_failure: false}.Run();
}

@test(tag = "tls_engine")
func test_tls_stream_cancel_precedes_deadline_during_final_flush() {
  TlsBoundaryWriteCase{cancel: true, expire: true, native_failure: false}.Run();
}

@test(tag = "tls_engine")
func test_tls_stream_cancel_precedes_native_flush_error() {
  TlsBoundaryWriteCase{cancel: true, expire: false, native_failure: true}.Run();
}

@test(tag = "tls_engine")
func test_tls_stream_cancel_after_native_read_before_plaintext() {
  var stream: TlsStream = TlsStream.TestNew(2, 0);
  (stream).TestHandshake();
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  let options: NetOperationOptions = NetOperationOptions{
    deadline: NetDeadline.After(Instant.Now().ToDurationSinceEpochish().ToNanoseconds(), 10000000000u64),
    cancellation: token
  };
  let future: AsyncFuture<TlsTransfer> = AsyncFuture<TlsTransfer>.TlsTestAdmit(stream.ReadAsync(16, options));
  nyra_tls_test_boundary_arm(0);
  var spawned: Result<Thread, ThreadError> = Thread.Spawn(
    lambda[copy token]() -> void {
      let reached: int32 = nyra_tls_test_boundary_wait();
      token.Cancel();
      nyra_tls_test_boundary_release();
      AssertTrueMsg(reached == 1, "worker reaches successful native-read rendezvous");
    }
  );
  AssertTrueMsg(spawned.IsOk(), "read cancellation worker starts");
  var worker: Thread = move((spawned.get_if<Thread>()) as Thread);
  let result: TlsTransfer = (stream).TestPump(future);
  AssertTrueMsg(
    worker.Join().IsOk() && nyra_tls_test_boundary_hit() == 1,
    "read cancellation precedes protocol processing"
  );
  (result).TestTlsError(TlsErrorKind.Cancelled);
  AssertTrueMsg(
    result.bytes_transferred == 0 && result.buffer.Len() == 0 && !result.eof,
    "cancelled encrypted input is not published as plaintext or EOF"
  );
  (stream).TestRetired();
  AssertTrueMsg(nyra_tls_test_server_join() == 0, "read-boundary peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_shutdown_cancel_after_local_alert() {
  var stream: TlsStream = TlsStream.TestNew(3, 0);
  (stream).TestHandshake();
  nyra_tls_test_write_controls(0, 0, -1);
  let token: NetCancellation = (NetCancellation.NewWakeable().get_if<NetCancellation>()) as NetCancellation;
  let options: NetOperationOptions = NetOperationOptions{
    deadline: NetDeadline.After(Instant.Now().ToDurationSinceEpochish().ToNanoseconds(), 10000000000u64),
    cancellation: token
  };
  let future: AsyncFuture<TlsTransfer> = AsyncFuture<TlsTransfer>.TlsTestAdmit(stream.ShutdownAsync(options));
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  let pointer: *mut TlsStream = &mut stream;
  future.RegisterContinuation(
    lambda[copy pointer, copy counter]() -> void {
      unsafe {
        (*pointer).TestRetired();
        (*pointer).Close();
      }

      var value: arc<TlsStreamTestCounter> = counter;
      value.hits = value.hits + 1;
    }
  );
  var rounds: int32 = 0;
  while nyra_tls_test_written_bytes() == 0 && !future.is_completed && rounds < 5000 {
    AssertTrueMsg(stream.Poll(0).IsOk(), "shutdown sends its local alert");
    rounds = rounds + 1;
  }

  AssertTrueMsg(
    nyra_tls_test_written_bytes() > 0 && !future.is_completed,
    "local alert alone leaves shutdown awaiting the peer"
  );
  token.Cancel();
  let result: TlsTransfer = (stream).TestPump(future);
  (result).TestTlsError(TlsErrorKind.Cancelled);
  AssertTrueMsg(
    result.bytes_transferred == 0 && !result.eof && counter.hits == 1,
    "cancelled shutdown publishes one terminal result"
  );
  stream.Close();
  AssertTrueMsg(
    stream.Poll(0).IsOk() && counter.hits == 1,
    "repeated retirement cannot republish shutdown"
  );
  AssertTrueMsg(nyra_tls_test_server_join() == 0, "cancelled shutdown peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_close_pending_write_after_cancel() {
  var stream: TlsStream = TlsStream.TestNew(3, 0);
  (stream).TestHandshake();
  nyra_tls_test_write_controls(317, 5, -1);
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{
    deadline: NetDeadline.After(Instant.Now().ToDurationSinceEpochish().ToNanoseconds(), 10000000000u64),
    cancellation: token
  };
  let payload: NetBuffer = NetBuffer.TlsTestPattern(200000);
  let future: AsyncFuture<TlsTransfer> = AsyncFuture<TlsTransfer>.TlsTestAdmit(stream.WriteAllAsync(payload, options));
  var rounds: int32 = 0;
  while nyra_tls_test_written_bytes() < 20000 && !future.is_completed && rounds < 5000 {
    AssertTrueMsg(stream.Poll(0).IsOk(), "write commits a plaintext prefix before Close");
    rounds = rounds + 1;
  }

  AssertTrueMsg(
    !future.is_completed && nyra_tls_test_written_bytes() >= 20000 && stream.RetainedBytes() > 0,
    "Close interrupts retained partial write"
  );
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(
    lambda[copy pointer, copy counter]() -> void {
      unsafe {
        (*pointer).TestRetired();
        (*pointer).Close();
        AssertTrueMsg(
          (*pointer).Poll(0).IsOk() && (*pointer).ReadAsync(1, NetOperationOptions.TlsTestDefault()).IsErr(),
          "Close callback cannot revive the connection"
        );
      }

      var value: arc<TlsStreamTestCounter> = counter;
      value.hits = value.hits + 1;
    }
  );
  token.Cancel();
  stream.Close();
  AssertTrueMsg(
    future.is_completed && counter.hits == 1,
    "explicit Close completes before any further Poll"
  );
  let result: TlsTransfer = (future.GetResult().get_if<TlsTransfer>()) as TlsTransfer;
  (result).TestTlsError(TlsErrorKind.Closed);
  AssertTrueMsg(
    result.bytes_transferred > 0 && result.bytes_transferred < payload.Len(),
    "Close preserves accepted prefix without replay"
  );
  stream.Close();
  AssertTrueMsg(
    stream.Poll(0).IsOk() && counter.hits == 1,
    "later cancellation processing cannot rewrite Closed"
  );
  AssertTrueMsg(nyra_tls_test_server_join() == 0, "closed partial-write peer retires");
}

@test(tag = "tls_engine")
func test_tls_stream_shutdown_callback_and_late_cancel() {
  var stream: TlsStream = TlsStream.TestNew(0, 0);
  (stream).TestHandshake();
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{
    deadline: NetDeadline.After(Instant.Now().ToDurationSinceEpochish().ToNanoseconds(), 10000000000u64),
    cancellation: token
  };
  let future: AsyncFuture<TlsTransfer> = AsyncFuture<TlsTransfer>.TlsTestAdmit(stream.ShutdownAsync(options));
  let pointer: *mut TlsStream = &mut stream;
  let counter: arc<TlsStreamTestCounter> = new arc<TlsStreamTestCounter>{};
  future.RegisterContinuation(
    lambda[copy pointer, copy counter, copy token]() -> void {
      unsafe {
        (*pointer).TestRetired();
        AssertTrueMsg(
          (*pointer).Poll(0).IsOk() && (*pointer).ShutdownAsync(NetOperationOptions.TlsTestDefault()).IsErr(),
          "successful shutdown callback observes closed protocol ownership"
        );
        (*pointer).Close();
      }

      token.Cancel();
      var value: arc<TlsStreamTestCounter> = counter;
      value.hits = value.hits + 1;
    }
  );
  let result: TlsTransfer = (stream).TestPump(future);
  AssertTrueMsg(
    result.error == nil && result.bytes_transferred == 0 && counter.hits == 1,
    "cancellation after publication cannot replace successful shutdown"
  );
  AssertTrueMsg(
    stream.Poll(0).IsOk()
      && counter.hits == 1
      && ((future.GetResult().get_if<TlsTransfer>()) as TlsTransfer).error == nil,
    "completed Future remains stable after callback Close and cancellation"
  );
  AssertTrueMsg(nyra_tls_test_server_join() == 0, "successful shutdown peer observed both notifications");
}
