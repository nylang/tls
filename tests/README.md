# TLS engine acceptance

The latest [stream receipt](../docs/stream-acceptance-2026-10-27.json) records local
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
path ABI and POSIX loopback peer are linked only into the test executable. The
acceptance net_core adapter renames its write function so the test fixture can
force partial progress, WouldBlock and a native error. Production adapter builds
use the original symbol; no product API or production test hook is added.

## Remaining gates

- Full certificate chain/limit/algorithm matrices, tampered records, allocation failures,
  changing read retry arguments, key updates and post-handshake messages.
- Broader readiness/native failure matrices, simultaneous native events and late
  cancellation/shutdown transitions beyond the accepted controlled cases.
- Other desktop hosts, mobile builds/runtime, system trust and portable delivery.
- Release CI and public repository origin; this is a local package candidate.

See [the maintained TLS roadmap](../ROADMAP.md). No HTTPS, FIPS, public package
release or complete absence of memory leaks is established by these results.
