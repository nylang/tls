// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module TlsSessionEngine;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";
import "interface/stream.ni";
import "interface/channel.ni";

/** @brief Language ownership and public error mapping around the private TLS bridge. */

struct TlsNativeResult {
  status: int32;
  error: int32;
  count: intptr;
}

@extern("C") func nyra_tls_client_new(
  peer: *const uint8,
  peer_size: intptr,
  ca_file: *const uint8,
  ca_size: intptr,
  alpn: *const uint8,
  alpn_size: intptr,
  capacity: int32,
  out: *mut *mut uint8
) -> int32;

@extern("C") func nyra_tls_drop(handle: *mut uint8) -> void;

@extern("C") func nyra_tls_step(
  handle: *mut uint8,
  operation: int32,
  input: *const uint8,
  output: *mut uint8,
  size: intptr,
  out: *mut TlsNativeResult
) -> void;

@extern("C") func nyra_tls_end_input(handle: *mut uint8) -> int32;

@extern("C") func nyra_tls_pending_output(handle: *mut uint8) -> intptr;

/** @brief Sole owner of a private TLS engine; default/moved-from values are closed. */
pub struct TlsSession {
  handle: *mut uint8;
}

func tls_error(code: int32) -> TlsError {
  var kind: TlsErrorKind = TlsErrorKind.Protocol;
  if code == 1 {
    kind = TlsErrorKind.InvalidArgument;
  } else if code == 2 {
    kind = TlsErrorKind.TrustUnavailable;
  } else if code == 3 {
    kind = TlsErrorKind.CertificateRejected;
  } else if code == 4 {
    kind = TlsErrorKind.PeerNameMismatch;
  } else if code == 6 {
    kind = TlsErrorKind.UnexpectedEof;
  } else if code == 7 {
    kind = TlsErrorKind.Closed;
  } else if code == 8 {
    kind = TlsErrorKind.InvalidState;
  } else if code == 9 {
    kind = TlsErrorKind.ResourceExhausted;
  }

  return TlsError{kind: kind};
}

func tls_progress(value: ref TlsNativeResult) -> Result<TlsProgress, TlsError> {
  if value.error != 0 {
    return tls_error(value.error);
  }

  var state: TlsStepState = TlsStepState.Complete;
  if value.status == 1 {
    state = TlsStepState.NeedInput;
  } else if value.status == 2 {
    state = TlsStepState.NeedOutput;
  } else if value.status == 3 {
    state = TlsStepState.PeerClosed;
  }

  return TlsProgress{state: state, bytes_transferred: value.count};
}

func tls_step(
  session: ref mut TlsSession,
  operation: int32,
  input: *const uint8,
  output: *mut uint8,
  size: intptr,
  options: ref NetOperationOptions
) -> Result<TlsProgress, TlsError> {
  let checked: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  let failure: NetError? = checked.get_if<NetError>();
  if failure != nil {
    session.Close();
    let error: NetError = failure as NetError;
    if error.kind == NetErrorKind.Cancelled {
      return TlsError{kind: TlsErrorKind.Cancelled};
    }

    return TlsError{kind: TlsErrorKind.TimedOut};
  }

  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(session.handle, operation, input, output, size, &mut result);

  return tls_progress(result);
}

/**
 * @brief Transfer ownership and leave the source closed.
 * @returns The TlsSession value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(TlsSession) operator move() -> TlsSession {
  let handle: *mut uint8 = self.handle;
  self.handle = 0 as *mut uint8;

  return TlsSession{handle: handle};
}

/** @brief Release the native engine during language destruction. */
pub method(TlsSession) operator drop() -> void {
  self.Close();
}

/**
 * @brief Create a verified TLS client with bounded ciphertext queues and no transport ownership.
 * @returns Session, validation/resource failure, or TrustUnavailable if CA loading fails.
 * @note No verification bypass exists. OpenSSL and native C stay private implementation details.
 */
pub static method(TlsSession) NewClient(config: ref TlsClientConfig) -> Result<TlsSession, TlsError> {
  var handle: *mut uint8 = 0 as *mut uint8;
  var capacity: int32 = config.ciphertext_capacity;
  if capacity == 0 {
    capacity = 32768;
  }

  let code: int32 = nyra_tls_client_new(config.peer_name.data as *const uint8, config.peer_name.length as intptr,
    config.ca_file.data as *const uint8, config.ca_file.length as intptr,
    config.alpn.data as *const uint8, config.alpn.length as intptr, capacity, &mut handle);
  if code != 0 {
    return tls_error(code);
  }

  return TlsSession{handle: handle};
}

/**
 * @brief Advance the handshake once; feed input or drain output before retrying as indicated.
 * @returns Complete only after certificate and identity verification, progress need, or failure.
 * @note Controls use NetClock's origin. Expiration/cancellation closes the engine before return.
 */
pub method(TlsSession) HandshakeStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 0, 0 as *const uint8, 0 as *mut uint8, 0 as intptr, options);
}

/**
 * @brief Read up to 16384 plaintext bytes into borrowed writable storage; empty buffers are
 *   no-ops.
 * @returns Plaintext progress, input/output need, authenticated PeerClosed, or failure.
 * @note A pending read excludes writes. Caller storage is never retained; retry with the same
 *   size. Unexpected transport EOF is UnexpectedEof, not authenticated closure.
 */
pub method(TlsSession) ReadStep(
  buffer: ref NetMutableBytes,
  options: ref NetOperationOptions
) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 1, 0 as *const uint8, buffer.Data(), buffer.Len(), options);
}

/**
 * @brief Write up to 16384 plaintext bytes; retains an internal bounded copy across retry needs.
 * @returns Count only when the complete supplied block is accepted by TLS; zero while pending.
 * @note Retry with identical bytes/length; a changed retry is InvalidState. No caller pointer is
 *   retained. A pending write excludes reads/shutdown. TLS acceptance does not flush TCP.
 */
pub method(TlsSession) WriteStep(
  buffer: ref NetBytes,
  options: ref NetOperationOptions
) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 2, buffer.Data(), 0 as *mut uint8, buffer.Len(), options);
}

/**
 * @brief Drive bidirectional close_notify after finishing any pending write; may abandon a read.
 * @returns Complete when both close notifications are processed, progress need, or failure.
 * @note Drain all queued output before retiring the transport. Controls still apply to shutdown.
 */
pub method(TlsSession) ShutdownStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 3, 0 as *const uint8, 0 as *mut uint8, 0 as intptr, options);
}

/**
 * @brief Copy as much incoming ciphertext as the bounded queue admits; retain any unconsumed
 *   suffix.
 * @returns Consumed byte count; zero means drive the engine to make input space, or error.
 * @note No borrowed data is retained. This method does not perform protocol processing or wait.
 */
pub method(TlsSession) FeedCiphertext(buffer: ref NetBytes) -> Result<intptr, TlsError> {
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 4, buffer.Data(), 0 as *mut uint8, buffer.Len(), &mut result);
  if result.error != 0 {
    return tls_error(result.error);
  }

  return result.count;
}

/**
 * @brief Remove queued ciphertext into borrowed storage; preserve unsent bytes until transport
 *   accepts them.
 * @returns Byte count, zero if output is empty, or error. Never waits or retains caller storage.
 */
pub method(TlsSession) DrainCiphertext(buffer: ref NetMutableBytes) -> Result<intptr, TlsError> {
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 5, 0 as *const uint8, buffer.Data(), buffer.Len(), &mut result);
  if result.error != 0 {
    return tls_error(result.error);
  }

  return result.count;
}

/**
 * @brief Number of queued outbound ciphertext bytes; closed sessions return zero.
 * @returns Number of queued outbound ciphertext bytes; closed sessions return zero.
 */
pub method(TlsSession) PendingCiphertext() -> intptr {
  return nyra_tls_pending_output(self.handle);
}

/**
 * @brief Mark transport EOF after feeding all received bytes; next protocol step authenticates
 *   closure.
 * @returns Ok with Unit on success; Err with TlsError on the failure paths described above.
 */
pub method(TlsSession) EndInput() -> Result<Unit, TlsError> {
  let code: int32 = nyra_tls_end_input(self.handle);
  if code != 0 {
    return tls_error(code);
  }

  return UnitValue();
}

/**
 * @brief Owned negotiated ALPN string after handshake, empty if absent, or a state failure.
 * @returns Ok with string on success; Err with TlsError on the failure paths described above.
 */
pub method(TlsSession) SelectedAlpn() -> Result<string, TlsError> {
  var bytes: <uint8>[255] = <uint8>[255] {
  };
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 6, 0 as *const uint8, &mut bytes[0], 255 as intptr, &mut result);
  if result.error != 0 {
    return tls_error(result.error);
  }

  return string.ViewFrom(&bytes[0] as *const int8, result.count as int32).Substring(0, result.count as int32);
}

/**
 * @brief Whether the value owns an engine; does not prove handshake success or peer liveness.
 * @returns Whether the value owns an engine; does not prove handshake success or peer liveness.
 */
pub method(TlsSession) IsOpen() -> bool {
  return self.handle != nil;
}

/** @brief Invalidate before native cleanup so repeated Close/drop is inert. */
pub method(TlsSession) Close() -> void {
  let handle: *mut uint8 = self.handle;
  self.handle = 0 as *mut uint8;
  nyra_tls_drop(handle);
}

/**
 * @brief Probe available authenticated plaintext without reserving a read on NeedInput.
 * @param buffer Exactly 16384 writable bytes, borrowed only during this call; unchanged without
 *   data.
 * @returns Complete with initialized plaintext count, NeedInput, NeedOutput, PeerClosed, or
 *   error.
 * @note Requires verified handshake and no ordinary pending read/write. NeedInput transfers no
 *   bytes and permits a later WriteStep; it does not assert absence of queued ciphertext.
 *   NeedOutput reserves this probe: drain ciphertext, then retry ProbeReadStep before any other
 *   protocol operation. Retry storage belongs to the engine, never to the caller. Feed/drain
 *   preserve their bounds; callers retain unsent ciphertext and original controls. No I/O,
 *   waiting, asynchronous operation, socket access or TLS stream contract is added.
 */
pub method(TlsSession) ProbeReadStep(
  buffer: ref NetMutableBytes,
  options: ref NetOperationOptions
) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 7, 0 as *const uint8, buffer.Data(), buffer.Len(), options);
}
