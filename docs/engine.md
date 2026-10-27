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

Acceptance injects twelve constructor failure scenarios into a separately compiled
bridge object. It counts private library contexts, bridge-owned SSL context
references, SSL sessions, state
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

## Runtime allocation failures

Each client owns an independent OpenSSL library context, used by SSL_CTX_new_ex
for algorithm fetching. Lazy provider registration and algorithm caches are not
shared between client sessions. The session releases SSL/BIO owners before its
library context; constructor rollback releases the temporary SSL_CTX reference
before freeing the context. The public API and explicit PEM verification policy
are unchanged. Creating a session performs independent provider initialization;
this isolation does not claim shared-context performance or a provider-memory cap.

Fatal operations inspect the complete provider error queue after SSL_get_error,
including allocation errors hidden beneath later SSL wrapper errors. An observed
malloc failure or X509 out-of-memory result reports ResourceExhausted with zero
new plaintext and terminal protocol state. When the provider discards the
allocation diagnostic, the existing terminal provider error fallback applies:
Protocol, or CertificateRejected/PeerNameMismatch when verification retained that
result. The bridge cannot infer the lost allocation cause. Optional
provider allocation failures can be tolerated when OpenSSL completes successfully.

The runtime allocation harness installs CRYPTO_set_mem_functions before provider
initialization in a fresh test process for each allocation index. It measures a
healthy operation, then independently fails each observed allocation in that
operation. Covered steps are the initial ClientHello, an authenticated read, the
first application write and first close_notify for TLS 1.2/1.3, plus a TLS 1.3
requested-KeyUpdate read. A later increment also sweeps all client handshake
steps after the initial ClientHello through authentication/completion in TLS
1.2/1.3. Peer work and relay storage are outside the injection window. A step
with no observed allocation has a healthy baseline
only. Each run validates plaintext/counts or terminal retirement, creates a healthy
replacement connection in the same process, and checks that hook-tracked provider
allocations reach zero after OPENSSL_cleanup. Allocator hooks exist only in the
test executable; the bridge and production process retain their normal allocators.

This is a bounded, single-failure sweep of observed operation-window allocations.
It does not cover every certificate/algorithm/provider configuration, failure-only
allocation branch, repeated/simultaneous OOM, renegotiation, or Nyra runtime allocations. Provider
static libraries are not claimed to have been built with sanitizers.

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
