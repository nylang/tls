# TLS implementation roadmap

Backend decision: OpenSSL, selected by the user on 2026-10-27. This independent
package owns TLS. net_core remains a transport dependency and does not import
this package. HTTP/HTTPS and remote package downloads remain separate consumers.
The compiler language pipeline is unchanged.

## T1 — Verified bounded client engine

- [x] Pin OpenSSL 3.5.9 LTS archive, hash and license/update policy.
- [x] Private native bridge; no OpenSSL/native-descriptor public API.
- [x] Move-only drop-owned session and provider-independent public errors.
- [x] Mandatory chain/DNS/IP SAN verification, explicit PEM trust and DNS SNI.
- [x] TLS 1.2/1.3 and optional ALPN; reject CN-only identity and obsolete TLS.
- [x] Bounded BIO pair and retained plaintext retry storage; both readiness directions.
- [x] Handshake/read/write/shutdown progress, raw EOF versus close_notify.
- [x] net_core byte ranges, monotonic deadlines and cancellation precedence.
- [x] macOS native behavior, sanitized bridge tests, public-SDK facade tests,
      isolated replays and production fixture isolation.
- [x] TLS 1.2/1.3 altered authentication tags and replayed records release no
      unauthenticated/duplicate plaintext, fail terminally and preserve fresh sessions.
- [x] Four-cycle TLS 1.3 peer KeyUpdate sequences with and without requested replies,
      exact non-requesting responses and bidirectional application traffic.
- [x] Pending-read capacity rejection and caller-buffer replacement without retaining
      or modifying abandoned caller storage.
- [x] Complete/missing/wrong-key intermediate chains, CA constraints, server EKU,
      future validity, eight/nine-intermediate depth and below/above-256-KiB certificates.
- [x] Eleven constructor failure scenarios, each with eight rollback/recovery rounds;
      identity allocation errors stay ResourceExhausted and IP failures never retry as DNS/SNI.
- [x] Real provider allocation sweeps for initial ClientHello, authenticated read,
      first application write/close_notify and requested-KeyUpdate read; terminal
      failure, same-process recovery and cleanup of hook-tracked allocations.
- [x] Post-ClientHello TLS 1.2/1.3 handshake allocation sweeps through authentication,
      isolated client provider contexts, constructor context rollback and new-session
      recovery after failed lazy algorithm registration.
- [ ] Additional certificate algorithms/critical extensions, other provider/runtime
      allocation failures, remaining transitions and post-handshake messages.

The [certificate/constructor acceptance](docs/certificate-resource-acceptance-2026-10-27.json)
records the selected chain/size boundaries and scoped bridge-owner fault injection.
These checks do not claim exhaustive provider allocation failure or CA-store memory bounds.
The later [runtime allocation acceptance](docs/runtime-resource-acceptance-2026-10-27.json)
adds nine operation baselines and records exact single-allocation sweeps per host.
The subsequent [handshake allocation acceptance](docs/handshake-resource-acceptance-2026-10-27.json)
adds two full post-ClientHello windows and private-provider context rollback.

This is a client engine foundation. T1 completion does not claim a complete TLS
stream, system-trust integration, cross-platform acceptance or package release.

## T2 — net_core transport adapter

- [x] Move-owned TCP/TLS stream with caller-thread Future driving and bounded queues.
- [x] Preserve ciphertext/offsets across partial TryWrite; retain excess read input.
- [x] Drain output before waiting for input, including read/shutdown protocol progress.
- [x] Carry one absolute deadline and cancellation through all native readiness waits.
- [x] Preserve write retry payloads, plaintext progress and ownership on failure/drop.
- [x] Handle concurrent-operation admission, Close/reentry and abandonment cleanup.
- [x] Recheck controls after final flush; cancellation precedes a simultaneous
      native send error, and accepted plaintext progress is preserved.
- [x] Deterministic native read/write rendezvous, shutdown-wait cancellation,
      Close after cancel and stable completion under callback Close/late cancel.
- [x] macOS loopback transfers, forced partial I/O/WouldBlock/native send failure,
      timeout/cancel, truncation and authenticated peer/full shutdown using public net_core.

The macOS source candidate passes 21 TLS cases and 21 isolated replays (six engine
facade cases and 15 stream cases), plus 19 native bridge cases and production
fixture isolation. See [stream contracts](docs/stream.md) and
[acceptance](tests/README.md). The integration required a native compiler fix:
ARC-backed facades with deleted copy must be moved, never implicitly cloned.
SDK 1.0.0/1.0.1 compilers do not contain that fix. SDK 1.0.2 is the release
baseline; the runner also supports an explicit native candidate with a separately
identified SDK runtime. The subsequent [desktop acceptance](docs/desktop-acceptance-2026-10-27.json)
records the same 21 cases/replays and 19 native cases on macOS arm64, Linux x86_64
and Windows x86_64. macOS/Linux bridge cases use ASan/UBSan; Windows does not.
Windows also passes 40 targeted repetitions of the four fixture-sensitive cases.
The [protocol increment](docs/protocol-acceptance-2026-10-27.json) then passes
23 TLS cases/replays and 26 native cases on the same three hosts, including
requested-key-update stream transfers under short writes/WouldBlock and
tampered-input failure retirement followed by a healthy connection.
The later [control-boundary increment](docs/control-boundary-acceptance-2026-10-27.json)
adds eight stream cases and verifies the post-flush control check. Each host
also passes 80 targeted replays of these eight cases.
Remaining hosts, complete fault matrices and release acceptance remain T3.

## T3 — Platform trust and delivery

- [x] Linux x86_64 native compilation and behavior: 31 TLS cases, 31 isolated
      replays and 60 ASan/UBSan native scenarios using a fixed native compiler candidate.
- [x] Windows x86_64 native compilation and behavior: 31 TLS cases, 31 isolated
      replays and 60 unsanitized native scenarios; prior fixture-stability evidence is retained.
- [ ] macOS x86_64 acceptance.
- [ ] Explicit system-trust integration per advertised platform, or retain documented
      explicit CA-only support; never infer Keychain support from OpenSSL defaults.
- [ ] Android/iOS static builds, matching SDK/sysroot links and mobile runtime checks.
- [ ] Standalone public-SDK CI, source/dependency lock, licenses and portable consumers.
- [x] Public source repository at https://github.com/nylang/tls.
- [ ] Release artifacts, with exact source/library receipts.
- [ ] Recheck upstream advisories/pin before release and pass the complete advertised matrix.

Server configuration, mutual TLS and session resumption have no current public
implementation. They need explicit API/acceptance work before being advertised.
HTTP must retain a transport-independent parser/writer shared by TCP and TLS paths.
