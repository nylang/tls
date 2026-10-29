// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of TlsContractTests;

/** @brief Public TLS session ownership and operation controls against a fixture CA. */

@extern("C") func AddFail(count: int32) -> void;

@extern("C") func nyra_tls_test_ca_file() -> *const int8;

@extern("C") func nyra_tls_test_ca_size() -> int32;

func tls_test_assert(condition: bool, message: ref string) -> void {
  if !condition {
    Console.Eprintln(message);
    AddFail(1);
  }
}

func tls_test_config() -> TlsClientConfig {
  return TlsClientConfig{
    peer_name: "localhost",
    ca_file: string.ViewFrom(nyra_tls_test_ca_file(), nyra_tls_test_ca_size()),
    alpn: "http/1.1",
    ciphertext_capacity: 1024
  };
}

func tls_test_session() -> TlsSession {
  var result: Result<TlsSession, TlsError> = TlsSession.NewClient(tls_test_config());
  tls_test_assert(result.IsOk(), "verified client construction");

  return move((result.get_if<TlsSession>()) as TlsSession);
}

@test(tag = "tls_engine")
func test_tls_default_and_validation() {
  var empty: TlsSession = TlsSession{};
  tls_test_assert(!empty.IsOpen() && empty.PendingCiphertext() == 0, "default owner is closed");
  let closed: Result<TlsProgress, TlsError> = empty.HandshakeStep(NetOperationOptions{});
  tls_test_assert(closed.IsErr(), "default session rejects handshake");
  if closed.IsErr() {
    tls_test_assert(
      ((closed.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.Closed,
      "closed error category"
    );
  }

  empty.Close();
  empty.Close();
  var invalid: TlsClientConfig = tls_test_config();
  invalid.peer_name = "";
  tls_test_assert(TlsSession.NewClient(invalid).IsErr(), "empty peer name fails");
  invalid = tls_test_config();
  invalid.ciphertext_capacity = 1023;
  tls_test_assert(TlsSession.NewClient(invalid).IsErr(), "queue minimum enforced");
  invalid = tls_test_config();
  invalid.ca_file = "/missing/nyra-tls-ca";
  var missing: Result<TlsSession, TlsError> = TlsSession.NewClient(invalid);
  tls_test_assert(missing.IsErr(), "missing CA fails closed");
  if missing.IsErr() {
    tls_test_assert(
      ((missing.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.TrustUnavailable,
      "trust failure category"
    );
  }
}

@test(tag = "tls_engine")
func test_tls_move_and_idempotent_close() {
  var original: TlsSession = tls_test_session();
  var moved: TlsSession = move(original);
  tls_test_assert(moved.IsOpen(), "move transfers exactly one engine");
  tls_test_assert(moved.HandshakeStep(NetOperationOptions{}).IsOk(), "moved owner remains usable");
  moved.Close();
  moved.Close();
  tls_test_assert(!moved.IsOpen() && moved.PendingCiphertext() == 0, "close invalidates owner");
}

@test(tag = "tls_engine")
func test_tls_handshake_output_and_bounded_input() {
  var session: TlsSession = tls_test_session();
  let step: Result<TlsProgress, TlsError> = session.HandshakeStep(NetOperationOptions{});
  tls_test_assert(step.IsOk(), "initial handshake progresses without a socket");
  if step.IsOk() {
    tls_test_assert(
      ((step.get_if<TlsProgress>()) as TlsProgress).state == TlsStepState.NeedOutput,
      "flush ClientHello before waiting for input"
    );
  }

  tls_test_assert(
    session.PendingCiphertext() > 0 && session.PendingCiphertext() <= 1024,
    "outgoing BIO is bounded"
  );
  var storage: <uint8>[2048] = <uint8>[2048] {
  };
  let buffer: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    2048 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  let drained: Result<intptr, TlsError> = session.DrainCiphertext(buffer);
  tls_test_assert(drained.IsOk() && session.PendingCiphertext() == 0, "caller drains outgoing ciphertext");
  let input: NetBytes = buffer.AsReadOnly();
  let fed: Result<intptr, TlsError> = session.FeedCiphertext(input);
  tls_test_assert(fed.IsOk(), "input admission succeeds partially");
  if fed.IsOk() {
    tls_test_assert(((fed.get_if<intptr>()) as intptr) == 1024, "input quota admits only its capacity");
  }

  let full: Result<intptr, TlsError> = session.FeedCiphertext(input);
  tls_test_assert(full.IsOk(), "full queue reports zero progress");
  if full.IsOk() {
    tls_test_assert(((full.get_if<intptr>()) as intptr) == 0, "unconsumed ciphertext stays with caller");
  }
}

@test(tag = "tls_engine")
func test_tls_controls_cancel_before_timeout() {
  var session: TlsSession = tls_test_session();
  let token: NetCancellation = NetCancellation.New();
  token.Cancel();
  let options: NetOperationOptions = NetOperationOptions{deadline: NetDeadline.At(0u64), cancellation: token};
  let result: Result<TlsProgress, TlsError> = session.HandshakeStep(options);
  tls_test_assert(result.IsErr() && !session.IsOpen(), "cancellation releases engine");
  if result.IsErr() {
    tls_test_assert(
      ((result.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.Cancelled,
      "cancel takes precedence over expired deadline"
    );
  }
}

@test(tag = "tls_engine")
func test_tls_deadline_retires_pending_output() {
  var session: TlsSession = tls_test_session();
  tls_test_assert(session.HandshakeStep(NetOperationOptions{}).IsOk(), "start pending handshake");
  tls_test_assert(session.PendingCiphertext() > 0, "pending output exists");
  let result: Result<TlsProgress, TlsError> = session.HandshakeStep(
    NetOperationOptions{deadline: NetDeadline.At(0u64)}
  );
  tls_test_assert(
    result.IsErr() && !session.IsOpen() && session.PendingCiphertext() == 0,
    "timeout retires pending engine and output"
  );
  if result.IsErr() {
    tls_test_assert(
      ((result.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.TimedOut,
      "deadline error category"
    );
  }
}

@test(tag = "tls_engine")
func test_tls_drop_cycles() {
  var i: int32 = 0;
  while i < 64 {
    var session: TlsSession = tls_test_session();
    tls_test_assert(session.IsOpen(), "loop owner constructed");
    i = i + 1;
  }
}

@test(tag = "tls_engine")
func test_tls_probe_state_and_original_controls() {
  var storage: <uint8>[16384] = <uint8>[16384] {
  };
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    16384 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  var empty: TlsSession = TlsSession{};
  let closed: Result<TlsProgress, TlsError> = empty.ProbeReadStep(output, NetOperationOptions{});
  tls_test_assert(
    closed.IsErr() && ((closed.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.Closed,
    "probe default owner is closed"
  );
  var session: TlsSession = tls_test_session();
  let premature: Result<TlsProgress, TlsError> = session.ProbeReadStep(output, NetOperationOptions{});
  tls_test_assert(
    premature.IsErr()
      && ((premature.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.InvalidState
      && session.IsOpen(),
    "probe requires handshake without poisoning admission"
  );
  let token: NetCancellation = NetCancellation.New();
  token.Cancel();
  let cancelled: Result<TlsProgress, TlsError> = session.ProbeReadStep(
    output,
    NetOperationOptions{cancellation: token, deadline: NetDeadline.At(0u64)}
  );
  tls_test_assert(
    cancelled.IsErr()
      && ((cancelled.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.Cancelled
      && !session.IsOpen(),
    "probe keeps original cancellation precedence and retires session"
  );
  var expired: TlsSession = tls_test_session();
  let timeout: Result<TlsProgress, TlsError> = expired.ProbeReadStep(
    output,
    NetOperationOptions{deadline: NetDeadline.At(0u64)}
  );
  tls_test_assert(
    timeout.IsErr()
      && ((timeout.get_if<TlsError>()) as TlsError).kind == TlsErrorKind.TimedOut
      && !expired.IsOpen(),
    "probe deadline uses the existing monotonic origin and retires session"
  );
}
