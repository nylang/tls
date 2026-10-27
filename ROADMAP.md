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
- [ ] Broader invalid certificate chains, certificate limits, allocation failures,
      tampered records, write/read transition faults and TLS 1.3 post-handshake traffic.

This is a client engine foundation. T1 completion does not claim a complete TLS
stream, system-trust integration, cross-platform acceptance or package release.

## T2 — net_core transport adapter

- [x] Move-owned TCP/TLS stream with caller-thread Future driving and bounded queues.
- [x] Preserve ciphertext/offsets across partial TryWrite; retain excess read input.
- [x] Drain output before waiting for input, including read/shutdown protocol progress.
- [x] Carry one absolute deadline and cancellation through all native readiness waits.
- [x] Preserve write retry payloads, plaintext progress and ownership on failure/drop.
- [x] Handle concurrent-operation admission, Close/reentry and abandonment cleanup.
- [x] macOS loopback transfers, forced partial I/O/WouldBlock/native send failure,
      timeout/cancel, truncation and authenticated peer/full shutdown using public net_core.

The macOS source candidate passes 21 TLS cases and 21 isolated replays (six engine
facade cases and 15 stream cases), plus 19 native bridge cases and production
fixture isolation. See [stream contracts](docs/stream.md) and
[acceptance](tests/README.md). The integration required a native compiler fix:
ARC-backed facades with deleted copy must be moved, never implicitly cloned.
The published SDK compilers remain unsupported for this stream until that fix
is released; the runner supports an explicit native candidate and public SDK
runtime. Other hosts, complete fault matrices and release acceptance remain T3.

## T3 — Platform trust and delivery

- [ ] Linux/Windows native compilation and behavior; macOS x86_64 acceptance.
- [ ] Explicit system-trust integration per advertised platform, or retain documented
      explicit CA-only support; never infer Keychain support from OpenSSL defaults.
- [ ] Android/iOS static builds, matching SDK/sysroot links and mobile runtime checks.
- [ ] Standalone public-SDK CI, source/dependency lock, licenses and portable consumers.
- [ ] Public repository origin and release artifacts, with exact source/library receipts.
- [ ] Recheck upstream advisories/pin before release and pass the complete advertised matrix.

Server configuration, mutual TLS and session resumption have no current public
implementation. They need explicit API/acceptance work before being advertised.
HTTP must retain a transport-independent parser/writer shared by TCP and TLS paths.
