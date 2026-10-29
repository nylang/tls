// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/**
 * @brief Bounded caller-driven TLS over net_core byte ranges, independent of native descriptors.
 * @note Sessions are move-only, single-threaded owners. Feed/drain ciphertext using a transport;
 *   the engine performs no socket I/O, DNS, waiting or background work.
 */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";

/** @brief Provider-independent TLS failure categories. */
pub enum TlsErrorKind {
  InvalidArgument,
  TrustUnavailable,
  CertificateRejected,
  PeerNameMismatch,
  Protocol,
  UnexpectedEof,
  Closed,
  InvalidState,
  ResourceExhausted,
  Cancelled,
  TimedOut,
}

/** @brief Copyable TLS error without OpenSSL pointers, layouts or error-queue lifetime. */
pub struct TlsError {
  kind: TlsErrorKind;
}

/** @brief Progress needed by a protocol operation; always drain pending output before waiting. */
pub enum TlsStepState {
  Complete,
  NeedInput,
  NeedOutput,
  PeerClosed
}

/**
 * @brief One protocol step; bytes_transferred counts plaintext only on successful read/write.
 * @note Complete may leave ciphertext queued. PeerClosed is authenticated close_notify, never
 *   raw transport EOF. NeedInput/NeedOutput transfer no plaintext ownership.
 */
pub struct TlsProgress {
  state: TlsStepState;
  bytes_transferred: intptr;
}

/**
 * @brief Client configuration copied by NewClient; defaults never disable verification.
 * @param peer_name Required ASCII DNS name or unbracketed IP literal; verifies DNS/IP SAN.
 * @param ca_file Required explicit PEM CA path; no implicit system or environment trust
 *   fallback.
 * @param alpn Optional single protocol of 1..255 bytes; empty means no ALPN offer.
 * @param ciphertext_capacity Per-direction BIO capacity, 1024..1048576; zero selects 32768.
 * @note TLS 1.2/1.3 only. Configuration strings need only outlive NewClient.
 */
pub struct TlsClientConfig {
  peer_name: string;
  ca_file: string;
  alpn: string;
  ciphertext_capacity: int32;
}

/** @brief Sole owner of a private TLS engine; default/moved-from values are closed. */
pub struct TlsSession;

/** @brief A live TLS engine cannot be copied. */
pub method(TlsSession) operator copy() -> TlsSession = delete;

/**
 * @brief Transfer ownership and leave the source closed.
 * @returns The TlsSession value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(TlsSession) operator move() -> TlsSession;

/** @brief Release engine resources; drop performs no network I/O or graceful shutdown. */
pub method(TlsSession) operator drop() -> void;

/**
 * @brief Create a verified TLS client with bounded ciphertext queues and no transport ownership.
 * @returns Session, validation/resource failure, or TrustUnavailable if CA loading fails.
 * @note No verification bypass exists. OpenSSL and native C stay private implementation details.
 */
pub static method(TlsSession) NewClient(config: ref TlsClientConfig) -> Result<TlsSession, TlsError>;

/**
 * @brief Advance the handshake once; feed input or drain output before retrying as indicated.
 * @returns Complete only after certificate and identity verification, progress need, or failure.
 * @note Controls use NetClock's origin. Expiration/cancellation closes the engine before return.
 */
pub method(TlsSession) HandshakeStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError>;

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
) -> Result<TlsProgress, TlsError>;

/**
 * @brief Write up to 16384 plaintext bytes; retains an internal bounded copy across retry needs.
 * @returns Count only when the complete supplied block is accepted by TLS; zero while pending.
 * @note Retry with identical bytes/length; a changed retry is InvalidState. No caller pointer is
 *   retained. A pending write excludes reads/shutdown. TLS acceptance does not flush TCP.
 */
pub method(TlsSession) WriteStep(
  buffer: ref NetBytes,
  options: ref NetOperationOptions
) -> Result<TlsProgress, TlsError>;

/**
 * @brief Drive bidirectional close_notify after finishing any pending write; may abandon a read.
 * @returns Complete when both close notifications are processed, progress need, or failure.
 * @note Drain all queued output before retiring the transport. Controls still apply to shutdown.
 */
pub method(TlsSession) ShutdownStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError>;

/**
 * @brief Copy as much incoming ciphertext as the bounded queue admits; retain any unconsumed
 *   suffix.
 * @returns Consumed byte count; zero means drive the engine to make input space, or error.
 * @note No borrowed data is retained. This method does not perform protocol processing or wait.
 */
pub method(TlsSession) FeedCiphertext(buffer: ref NetBytes) -> Result<intptr, TlsError>;

/**
 * @brief Remove queued ciphertext into borrowed storage; preserve unsent bytes until transport
 *   accepts them.
 * @returns Byte count, zero if output is empty, or error. Never waits or retains caller storage.
 */
pub method(TlsSession) DrainCiphertext(buffer: ref NetMutableBytes) -> Result<intptr, TlsError>;

/**
 * @brief Number of queued outbound ciphertext bytes; closed sessions return zero.
 * @returns Number of queued outbound ciphertext bytes; closed sessions return zero.
 */
pub method(TlsSession) PendingCiphertext() -> intptr;

/**
 * @brief Mark transport EOF after feeding all received bytes; next protocol step authenticates
 *   closure.
 * @returns Ok with Unit on success; Err with TlsError on the failure paths described above.
 */
pub method(TlsSession) EndInput() -> Result<Unit, TlsError>;

/**
 * @brief Owned negotiated ALPN string after handshake, empty if absent, or a state failure.
 * @returns Ok with string on success; Err with TlsError on the failure paths described above.
 */
pub method(TlsSession) SelectedAlpn() -> Result<string, TlsError>;

/**
 * @brief Whether the value owns an engine; does not prove handshake success or peer liveness.
 * @returns Whether the value owns an engine; does not prove handshake success or peer liveness.
 */
pub method(TlsSession) IsOpen() -> bool;

/** @brief Release the engine once without I/O; use ShutdownStep first for orderly TLS closure. */
pub method(TlsSession) Close() -> void;

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
) -> Result<TlsProgress, TlsError>;
