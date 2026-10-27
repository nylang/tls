# TLS acceptance

The current [certificate/constructor acceptance](../docs/certificate-resource-acceptance-2026-10-27.json)
records **23 Nyra cases, 23 isolated replays and 48 native scenarios** on the three
accepted desktop hosts, with matching source inputs and production isolation.
macOS/Linux native tests use ASan/UBSan; Windows is unsanitized.

Eleven certificate cases add complete/missing/wrong-key intermediate chains,
CA:FALSE/pathLenConstraint rejection, server EKU/time validation, depth eight/nine,
and valid-below/invalid-above-256-KiB certificate message sizes. Fixture keys and
certificates remain outside the package. Deep-chain fixtures reuse a test key
with distinct issuer names; signature verification remains enabled.

Eleven constructor fault scenarios each repeat eight injected failures and eight
healthy recoveries. The separately compiled bridge object intercepts acquisition,
adoption and release at context/trust/state/session/BIO/DNS/IP/SNI/ALPN boundaries;
it does not replace the process allocator or claim exhaustive provider-internal
OOM coverage. Bridge-owned resources return to zero after failure/drop. Regression
cases also require DNS/SNI allocation errors to remain ResourceExhausted and IP
allocation failure to abort without DNS/SNI fallback. Ordinary native archives and
Nyra production packages exclude all injection hooks.

The previous [protocol acceptance](../docs/protocol-acceptance-2026-10-27.json)
records **23 Nyra cases, 23 isolated replays and 26 native cases** on macOS arm64,
Linux x86_64 and Windows x86_64, with matching TLS/net_core inputs and production
fixture isolation. macOS/Linux bridge tests are ASan/UBSan instrumented;
Windows is unsanitized. Source compiler/public SDK runtime boundaries below
still apply; this is local validation without SDK promotion or publication.

Seven new native cases cover TLS 1.2/1.3 tag corruption and record replay,
terminal state/no plaintext publication, fresh-session recovery, four-cycle
requested/unrequested KeyUpdate sequences with exact reply flags, and pending
read capacity rejection/caller-buffer replacement. Two stream cases cover
requested key updates followed by a 64 KiB patterned transfer under partial
sends/WouldBlock, and an encrypted payload mutation with the record header
preserved. The latter keeps TCP connected until TLS classifies the error and
verifies complete retirement plus a healthy subsequent connection.
The two new stream cases also pass ten additional Windows rounds (20 targeted
replays), retained in the protocol summary with the executable hash.

The earlier [desktop summary](../docs/desktop-acceptance-2026-10-27.json) records
the final matching TLS/net_core source hashes on **macOS arm64, Linux x86_64 and
Windows x86_64**. Every host passes 21 Nyra cases, 21 isolated replays, 19 native
bridge cases, O2 production precompilation and production fixture isolation.
The bridge/test executable uses ASan/UBSan on macOS and Linux. Windows acceptance
is explicitly unsanitized, uses the MSVC static OpenSSL build without assembly,
and also passes 40 targeted repetitions of the four fixture-sensitive cases.
All compilers are source candidates with the ownership fix: macOS uses the
public SDK 1.0.0 runtime, Linux/Windows use 1.0.1. No SDK or package is promoted.

The earlier [stream receipt](../docs/stream-acceptance-2026-10-27.json) records local
**macOS arm64** TCP/Future integration using an explicit native compiler candidate
with the deleted-copy ARC ownership fix and the public SDK 1.0.0 runtime. It
identifies both compiler identities, TLS/net_core inputs, pinned OpenSSL, deployment
target and staged manifests. The earlier [engine-only receipt](../docs/acceptance-2026-10-27.json)
retains its original six-case/public-SDK-compiler evidence unchanged.

- 19 controlled native cases pass with ASan/UBSan instrumentation of the bridge
  and test executable. The upstream static OpenSSL libraries are built normally;
  neither their full test suite nor an instrumented full OpenSSL build is claimed.
- 21 Nyra cases pass (six engine facade and 15 stream), plus 21 isolated replays.
  The source candidate uses public SDK 1.0.0 runtime packages, with source fallback
  disabled. The published SDK compiler itself remains unsupported for the stream.
- O2 production precompilation succeeds without fixture/harness undefined imports.
  A separate ordinary net_core adapter build also has no TLS test interposition imports.

Native cases cover verified TLS 1.2/1.3, DNS/IP SAN, DNS SNI, ALPN, expired/untrusted/
wrong-name/CN-only rejection, ALPN mismatch, TLS 1.1 refusal, fragmented 16 KiB
payload with output backpressure, stable write retry/operation admission, TLS
reads, authenticated shutdown, unexpected EOF, missing explicit trust, embedded
NUL validation, bounded input and repeated construction/drop.

Facade cases cover default/invalid configuration, named error mapping, move/Close,
ClientHello output-first driving, input queue admission, cancellation-before-timeout,
retiring queued output at timeout and repeated language-managed drop.

Stream cases cover a 200,000-byte patterned loopback echo under forced 317-byte
TCP writes and periodic WouldBlock; retained write-buffer drop, input BIO
backpressure, authenticated peer/full shutdown; payload/root-slice admission and
stream move; handshake/read/shutdown deadlines; cross-thread wakeable cancellation;
partial-write cancellation and injected ConnectionReset with preserved native
code/progress; Close and successful-Poll continuation reentry; truncation after a
published plaintext prefix; identity rejection; pre-admission control precedence,
empty I/O, Future drop and 64-round descriptor recovery.

Run scripts/accept.py with --compiler pointing to a compatible native candidate,
a supplied public SDK, sibling net_core checkout and pinned built OpenSSL tree.
Published SDK 1.0.0/1.0.1 compilers are rejected before testing because their Core
ownership classifier clones deleted-copy ARC resource facades. The native fix
preserves the existing source spelling and has its own compiler regression.
See [README](../README.md) for the full command. Output directories must be
new/empty and outside the package. Staged manifests use SDK precompiled
stdlib/kernel; source manifests retain the NyraLang workspace dependency layout.

Certificates and private keys are generated only in the external acceptance
output. They are test fixtures, never user identity material or package assets.
The independent C peer communicates over deliberately fragmented BIO queues;
no public Internet service or private compiler source is involved. The fixture
path ABI and native loopback peer are linked only into the test executable. The
peer uses pthread/POSIX sockets on Unix and CRT threads/WinSock on Windows,
preserving injected partial sends, WouldBlock and the host's native reset code.
Descriptor recovery measures POSIX descriptors or Windows process handles.
One identical construction/drop round primes process-global OS/provider state
before the baseline, followed by 64 exact equality checks. No allowed-leak
offset is subtracted. As in net_core's acceptance fixture, Windows retains one
fixture-owned WinSock provider reference until process exit to keep provider
unload/reload outside each socket's measured lifecycle. The stream peer disables
TLS 1.3 session tickets so
immediate client Close tests do not race unrelated post-handshake writes;
the native engine peer retains its ordinary TLS 1.3 ticket behavior.
The acceptance net_core adapter renames its read/write functions so the test fixture can
force partial progress, WouldBlock, a native error and controlled ciphertext mutation. Production adapter builds
use the original symbol; no product API or production test hook is added.

## Remaining gates

- Additional certificate algorithms/critical extensions, provider-internal and
  runtime-operation allocation failures, malformed
  post-handshake messages, unsolicited authentication and key-update/fault combinations
  beyond the accepted repeated-update, replay and corruption cases.
- Broader readiness/native failure matrices, simultaneous native events and late
  cancellation/shutdown transitions beyond the accepted controlled cases.
- macOS x86_64, mobile builds/runtime, system trust and portable delivery.
- Release CI and published-SDK consumption; this remains a local source candidate.

See [the maintained TLS roadmap](../ROADMAP.md). No HTTPS, FIPS, public package
release or complete absence of memory leaks is established by these results.
