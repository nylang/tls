/** @brief Move-owned TCP/TLS streams with explicit caller-thread Future driving. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";

/**
 * @brief Exactly one named TLS or transport error; successful transfers have no error value.
 * @note Transport failures retain NetError's category and native code without remapping.
 */
pub struct TlsStreamError { tls_error: TlsError?; transport_error: NetError?; }
/**
 * @brief Completed plaintext operation, including progress before failure.
 * @note Reads own immutable buffer bytes; writes/control operations leave buffer empty.
 *       Write counts are TLS-accepted plaintext, not peer acknowledgement or guaranteed delivery.
 *       eof is true only after authenticated peer close_notify. Errors never manufacture EOF.
 */
pub struct TlsTransfer { bytes_transferred: intptr; buffer: NetBuffer; eof: bool; error: TlsStreamError?; }
/**
 * @brief Sole owner of TCP, TLS and a one-registration readiness driver; no hidden worker.
 * @note All methods/Future access remain on the caller thread. Only a retained cancellation
 *       token's Cancel may run elsewhere. At most one operation is pending per stream.
 */
pub struct TlsStream;
/** @brief Live streams cannot be copied. */
pub method(TlsStream) operator copy() -> TlsStream = delete;
/** @brief Transfer the stream and its pending operation without duplicating native ownership. */
pub method(TlsStream) operator move() -> TlsStream;
/** @brief Close resources and complete any outstanding operation with Closed. */
pub method(TlsStream) operator drop() -> void;
/**
 * @brief Create a client stream with a 1 MiB pending-payload limit, then move connection on success.
 * @returns Stream or configuration/driver failure; on failure connection is untouched.
 * @note The connection must have no outstanding I/O/readiness registrations. No handshake starts
 *       until HandshakeAsync is admitted and Poll is called. Configuration is copied immediately.
 */
pub static method(TlsStream) NewClient(connection: ref mut TcpConnection, config: ref TlsClientConfig) -> Result<TlsStream, TlsStreamError>;
/**
 * @brief Create with a nonnegative pending-payload limit; reads reserve requested bytes.
 * @param max_retained_bytes Writes charge the complete NetBuffer backing, even for a small slice.
 * @note Fixed stream/BIO/Future overhead and consumer-held completed buffers are outside this limit.
 *       One operation is admitted at a time; budget rejection never changes the active operation.
 */
pub static method(TlsStream) NewClientWithLimit(connection: ref mut TcpConnection, config: ref TlsClientConfig, max_retained_bytes: intptr) -> Result<TlsStream, TlsStreamError>;
/** @brief Enqueue verified handshake; completion also requires flushing all generated ciphertext. */
pub method(TlsStream) HandshakeAsync(options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError>;
/**
 * @brief Enqueue one partial plaintext read of 0..16384 bytes after handshake.
 * @returns Future with owned initialized bytes, authenticated EOF, or progress/error; no borrowed buffer.
 * @note Zero size is a no-op and does not mean EOF. Dropping the Future does not cancel the operation.
 */
pub method(TlsStream) ReadAsync(max_bytes: int32, options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError>;
/**
 * @brief Retain an immutable buffer and send all plaintext in stable 16 KiB TLS retry blocks.
 * @returns Future preserving TLS-accepted plaintext count on failure. Original buffer may drop immediately.
 * @note Admission/control errors before enqueue return the outer Result without retiring the stream.
 *       After enqueue, failure/cancellation/timeout retires TCP/TLS and completes the Future once.
 */
pub method(TlsStream) WriteAllAsync(buffer: ref NetBuffer, options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError>;
/**
 * @brief Enqueue bidirectional close_notify; success flushes output and retires TCP/TLS before publication.
 * @note The same absolute deadline/cancellation covers the complete shutdown exchange.
 */
pub method(TlsStream) ShutdownAsync(options: ref NetOperationOptions) -> Result<AsyncFuture<TlsTransfer>, TlsStreamError>;
/**
 * @brief Advance up to eight bounded transport/protocol rounds and at most one native wait.
 * @param maximum_wait_ms Zero polls; -1 permits the operation's original absolute control budget.
 * @returns Zero or one completed operation, or invalid Poll arguments/reentry failure.
 * @note Idle returns immediately. Read/write readiness is chosen by TLS progress and unsent ciphertext.
 *       Pending state/resources are detached before synchronous Future continuations run.
 */
pub method(TlsStream) Poll(maximum_wait_ms: int32) -> Result<int32, TlsStreamError>;
/** @brief Zero or one pending operation; completed consumer-held Futures are excluded. */
pub method(TlsStream) PendingCount() -> int32;
/** @brief Payload backing bytes charged to the pending operation, excluding fixed queue overhead. */
pub method(TlsStream) RetainedBytes() -> intptr;
/** @brief Owned negotiated ALPN after handshake; not available after stream retirement. */
pub method(TlsStream) SelectedAlpn() -> Result<string, TlsStreamError>;
/** @brief Whether the stream owns a live transport/engine; not a peer-liveness probe. */
pub method(TlsStream) IsOpen() -> bool;
/**
 * @brief Retire all registrations/TCP/TLS and complete pending work with Closed; repeated calls are inert.
 * @note Does not perform graceful TLS shutdown. Call ShutdownAsync and drive its Future first.
 */
pub method(TlsStream) Close() -> void;
