// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Optional caller-thread TLS channel for response-first application scheduling. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";
import "interface/stream.ni";

/**
 * @brief Read probe outcome; Again asks for another bounded nonblocking drive.
 * @note RetryWrite requires the identical WriteAvailable retry before probing again.
 */
pub enum TlsChannelReadState {
  Ready,
  NeedRead,
  NeedWrite,
  Again,
  RetryWrite
}

/** @brief Owned authenticated plaintext/EOF or terminal progress/error, plus advisory readiness. */
pub struct TlsChannelRead {
  state: TlsChannelReadState;
  transfer: TlsTransfer;
}

/** @brief Write scheduling result; RetryRead preserves an active provider read retry. */
pub enum TlsChannelWriteState {
  Ready,
  NeedRead,
  NeedWrite,
  RetryRead
}

/**
 * @brief TLS-accepted plaintext progress plus the provider's next permissible scheduling action.
 */
pub struct TlsChannelWrite {
  state: TlsChannelWriteState;
  transfer: TlsTransfer;
}

/**
 * @brief Move-only TCP/TLS owner; caller-thread synchronous steps, no hidden worker or
 *   concurrent calls.
 * @note This separate opt-in API preserves TlsStream's one-pending-Future contract. It can probe
 *   reads while application ciphertext awaits TCP acceptance, provided the provider has no retry
 *   barrier.
 */
pub struct TlsChannel;

/** @brief Channel ownership cannot be copied. */
pub method(TlsChannel) operator copy() -> TlsChannel = delete;

/**
 * @brief Transfer the sole channel owner.
 * @returns The TlsChannel value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(TlsChannel) operator move() -> TlsChannel;

/** @brief Abort-close TCP, TLS and all readiness registrations. */
pub method(TlsChannel) operator drop() -> void;

/**
 * @brief Validate TLS configuration before adopting TCP; failure leaves connection untouched.
 * @returns Ok with TlsChannel on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note Require no outstanding socket I/O/readiness. Zero ciphertext_capacity selects 65536;
 *   explicit capacity must be 32768..1048576, admitting a full 16 KiB record before socket flush.
 *   Peer verification and explicit PEM trust are identical to TlsSession/TlsStream.
 */
pub static method(TlsChannel) NewClient(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig
) -> Result<TlsChannel, TlsStreamError>;

/**
 * @brief Complete verified handshake and flush its ciphertext using the supplied original
 *   controls.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 */
pub method(TlsChannel) Handshake(options: ref NetOperationOptions) -> Result<Unit, TlsStreamError>;

/**
 * @brief Owned selected ALPN after handshake, or state/terminal failure.
 * @returns Ok with string on success; Err with TlsStreamError on the failure paths described
 *   above.
 */
pub method(TlsChannel) SelectedAlpn() -> Result<string, TlsStreamError>;

/**
 * @brief Probe up to 16 KiB plaintext in at most eight nonblocking rounds, without flushing
 *   application output.
 * @returns Ok with TlsChannelRead on success; Err with TlsStreamError on the failure paths
 *   described above.
 * @note NeedRead permits writing; NeedWrite requires flushing output and retrying this read
 *   first. Ready carries owned data or authenticated EOF; errors never manufacture EOF. Partial
 *   native ciphertext stays owned until admitted. Transport/provider failures and controls retire
 *   the channel.
 */
pub method(TlsChannel) ReadAvailable(
  options: ref NetOperationOptions
) -> Result<TlsChannelRead, TlsStreamError>;

/**
 * @brief Accept at most one immutable 16 KiB plaintext block after flushing prior ciphertext.
 * @returns Ok with TlsChannelWrite on success; Err with TlsStreamError on the failure paths
 *   described above.
 * @note Charges entire backing (at most 16 KiB). Zero progress asks for Flush/readiness then
 *   retry with identical bytes; no caller pointer is retained. TLS acceptance does not assert TCP
 *   delivery. NeedRead/NeedWrite require waiting then retrying WriteAvailable with the same block;
 *   RetryRead requires ReadAvailable first. Admission errors leave the active state intact. Report
 *   any positive transfer count before handling its terminal error or parsing an early response.
 */
pub method(TlsChannel) WriteAvailable(
  buffer: ref NetBuffer,
  options: ref NetOperationOptions
) -> Result<TlsChannelWrite, TlsStreamError>;

/**
 * @brief Flush at most eight bounded ciphertext attempts; false means pending output, never
 *   discarded.
 * @returns Ok with bool on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note No application plaintext is accepted here. Failures/controls retire all channel
 *   resources.
 */
pub method(TlsChannel) Flush(options: ref NetOperationOptions) -> Result<bool, TlsStreamError>;

/**
 * @brief Wait for either requested direction, without consuming input or borrowing output
 *   storage.
 * @param maximum_wait_ms Zero polls, -1 original controls; nonnegative bounds do not refresh
 *   deadlines.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note One call owns at most two advisory readiness registrations and retires both before
 *   return.
 */
pub method(TlsChannel) Wait(
  readable: bool,
  writable: bool,
  maximum_wait_ms: int32,
  options: ref NetOperationOptions
) -> Result<Unit, TlsStreamError>;

/**
 * @brief Perform bidirectional close_notify after all application output is flushed and no retry
 *   is pending.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note InvalidState leaves the channel intact. Close/drop aborts without flushing remaining
 *   upload.
 */
pub method(TlsChannel) Shutdown(options: ref NetOperationOptions) -> Result<Unit, TlsStreamError>;

/**
 * @brief Whether the channel owns a live TCP/TLS engine, not a peer-liveness probe.
 * @returns Whether the channel owns a live TCP/TLS engine, not a peer-liveness probe.
 */
pub method(TlsChannel) IsOpen() -> bool;

/** @brief Abort once without sending queued application data; preserve the first terminal error. */
pub method(TlsChannel) Close() -> void;
