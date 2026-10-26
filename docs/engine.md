# Client engine contract

The public module is tls:tls.ny. The engine depends on public stdlib and net_core
APIs. All OpenSSL objects and bridge functions remain private. An application
keeps its TCP connection separate and drives this engine on one caller thread.
A session is never accessed concurrently and cannot be copied. Moving transfers
the sole owner; default and moved-from state has no native resource. Close/drop
releases resources without network operations. Explicit ShutdownStep drives
protocol closure first when orderly shutdown is required.

## Configuration and verification

NewClient copies peer/CA/ALPN values during construction. A nonempty explicit
PEM CA file is required; loading failure never falls back to platform trust or
environment default paths. No insecure verification switch exists. ASCII DNS
names configure SNI and DNS SAN verification. Unbracketed IP literals configure
IP SAN verification without SNI. Embedded NUL identity/path data and malformed
names are rejected. CN fallback and partial-label wildcards are disabled.

Only TLS 1.2/1.3 negotiate. Renegotiation and compression are disabled. The
certificate-list bound is 256 KiB and chain verification depth is eight. One
optional 1..255-byte ALPN protocol is offered; empty means no ALPN extension.
SelectedAlpn returns an owned copy only after a successful handshake. ALPN may
be absent; the application must validate its own negotiated protocol needs.

Each BIO direction is allocated once at configured capacity (1 KiB..1 MiB,
zero configuration selects 32 KiB). Write retry/read scratch storage is 16 KiB
each. These are queue bounds, not an assertion that all OpenSSL/provider/CA
storage fits in that amount. Every operation has bounded application payload
size; complete certificate-memory and allocation-failure acceptance remain open.

## Driving protocol progress

1. HandshakeStep advances the protocol and authenticates the peer before success.
2. Drain PendingCiphertext using DrainCiphertext, retaining unsent suffixes until
   the transport actually accepts them. Never discard a partial TCP write.
3. If input is needed, obtain ciphertext and FeedCiphertext only as much as is
   admitted. Keep the remaining suffix and retry after driving protocol progress.
4. Retry the outstanding protocol operation after input/output progress. Check
   PendingCiphertext even after Complete; TLS acceptance is not a TCP flush.

The output queue takes precedence over an OpenSSL WANT_READ indication whenever
a flight is waiting to be sent. Read/write direction alone does not choose socket
readiness. FeedCiphertext returning zero means input is full and needs protocol
processing, not that a socket should be polled for writability. DrainCiphertext
returning zero means no ciphertext is currently queued.

Protocol steps check the supplied NetOperationOptions with NetClock's monotonic
origin. Expiry/cancellation closes the engine before returning its named error;
queued plaintext/ciphertext is abandoned. All calls are nonblocking local work;
a future transport adapter must carry the same absolute deadline through every
TCP wait and prevent busy polling. This engine itself has no waits or callbacks.

## Read, write and shutdown states

One plaintext operation may be pending. A pending write blocks reads/shutdown;
its immutable internal retry copy survives caller buffer drop. Each retry must
supply identical bytes/length, which are checked before OpenSSL runs. A pending
read blocks writes and must retry with the same capacity; it retains only
internal scratch, never the caller's pointer. A write/read accepts at most
16 KiB. Empty operations are no-ops when no conflicting pending operation exists.

ShutdownStep can abandon a pending read but cannot abandon a pending write.
It sends and waits for close_notify; drain output before closing the transport.
EndInput marks raw transport EOF after all preceding ciphertext is fed. A read
returns PeerClosed only for authenticated close_notify; missing notification is
UnexpectedEof. Other fatal protocol/verification errors retire protocol access;
Close/drop remains valid. Outgoing alert bytes can still be drained after a fatal
protocol failure. Argument/state errors do not silently advance a pending write.

## Native API correctness

Every TLS operation clears the calling thread's error queue and immediately
classifies SSL_get_error on that thread, before another OpenSSL call. Stable
private result codes map once into provider-independent TlsErrorKind. Native
aggregate returns are not part of the Nyra FFI: the bridge writes explicit result
storage. The production package excludes fixture/harness imports.

Relevant upstream contracts: [BIO pairs](https://docs.openssl.org/3.5/man3/BIO_s_bio/),
[error classification](https://docs.openssl.org/3.5/man3/SSL_get_error/),
[write retry rules](https://docs.openssl.org/3.5/man3/SSL_write/),
and [peer identity](https://docs.openssl.org/3.5/man3/SSL_set1_host/).
