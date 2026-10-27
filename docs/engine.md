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
certificate-list bound is 256 KiB and chain verification permits eight intermediate
CA certificates, excluding the leaf and trusted root. One
optional 1..255-byte ALPN protocol is offered; empty means no ALPN extension.
SelectedAlpn returns an owned copy only after a successful handshake. ALPN may
be absent; the application must validate its own negotiated protocol needs.

Each BIO direction is allocated once at configured capacity (1 KiB..1 MiB,
zero configuration selects 32 KiB). Write retry/read scratch storage is 16 KiB
each. These are queue bounds, not an assertion that all OpenSSL/provider/CA
storage fits in that amount. Every operation has bounded application payload
size; complete certificate-memory and allocation-failure acceptance remain open.

The accepted chain matrix includes a complete intermediate chain with only its
root trusted; rejection of a missing/wrong-key/non-CA intermediate, an exceeded
pathLenConstraint, clientAuth-only EKU and a not-yet-valid leaf; and positive/
negative depth-eight/depth-nine boundaries. Valid near-limit and oversized leaf
fixtures preserve identity/key/EKU while varying non-critical opaque extensions.
The near-limit certificate succeeds; exceeding the message cap is terminal Protocol.

Malformed identities remain InvalidArgument. Allocation failure while installing
validated DNS/IP/SNI identity state is ResourceExhausted and returns no session.
For the pinned provider, an IP parse miss has no error, while IP parameter allocation
failure sets the error queue. The constructor distinguishes these cases before
considering a DNS identity, so resource failure cannot silently cause DNS fallback
or IP SNI. Explicit CA-loading failure still reports TrustUnavailable.

Acceptance injects eleven constructor failure scenarios into a separately compiled
bridge object. It counts bridge-owned context references, SSL sessions, state
storage and unattached BIO endpoints, including synthetic failure before BIO
adoption; each scenario repeats eight failure/healthy-recovery rounds. This does
not instrument arbitrary allocations inside OpenSSL or the Nyra runtime. Ordinary
native archives are symbol-checked to exclude the test hooks.

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

Authenticated-record failure, including an altered authentication tag or a
replayed TLS 1.2/1.3 record, reports Protocol with zero new plaintext. It cannot
be reinterpreted as PeerClosed or resumed by another handshake/read/write step.
The stream retires its transport and retained work before publishing the failure.

Peer-initiated TLS 1.3 KeyUpdate messages are handled within normal read/write
driving. They are never application bytes. A requested reply may be deferred
until the next write, which sends the non-requesting key-update response before
application data under the new sending key. Keep the usual output-draining and
partial-send rules; no separate public key-update operation is required.
The accepted cases cover four consecutive updates with and without reply
requests, and a requested update followed by a 64 KiB TCP/Future transfer under
forced short sends/WouldBlock. This is not a complete post-handshake matrix.

## Native API correctness

Every TLS operation clears the calling thread's error queue and immediately
classifies SSL_get_error on that thread, before another OpenSSL call. Stable
private result codes map once into provider-independent TlsErrorKind. Native
aggregate returns are not part of the Nyra FFI: the bridge writes explicit result
storage. The production package excludes fixture/harness imports.

Relevant upstream contracts: [BIO pairs](https://docs.openssl.org/3.5/man3/BIO_s_bio/),
[error classification](https://docs.openssl.org/3.5/man3/SSL_get_error/),
[write retry rules](https://docs.openssl.org/3.5/man3/SSL_write/),
[peer identity](https://docs.openssl.org/3.5/man3/SSL_set1_host/),
and [key updates](https://docs.openssl.org/3.5/man3/SSL_key_update/).
