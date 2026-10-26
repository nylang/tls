# TLS engine acceptance

The retained [2026-10-27 receipt](../docs/acceptance-2026-10-27.json) records a
local **macOS arm64** increment, not cross-platform or complete stream acceptance.
It identifies the public SDK/compiler, TLS/net_core source inputs, pinned OpenSSL
library inputs and the staged dependency manifests.

- 19 controlled native cases pass with ASan/UBSan instrumentation of the bridge
  and test executable. The upstream static OpenSSL libraries are built normally;
  neither their full test suite nor an instrumented full OpenSSL build is claimed.
- Six Nyra facade cases pass with public SDK 1.0.0, source fallback disabled,
  plus six isolated executable replays.
- O2 production precompilation succeeds without fixture/harness undefined imports.

Native cases cover verified TLS 1.2/1.3, DNS/IP SAN, DNS SNI, ALPN, expired/untrusted/
wrong-name/CN-only rejection, ALPN mismatch, TLS 1.1 refusal, fragmented 16 KiB
payload with output backpressure, stable write retry/operation admission, TLS
reads, authenticated shutdown, unexpected EOF, missing explicit trust, embedded
NUL validation, bounded input and repeated construction/drop.

Facade cases cover default/invalid configuration, named error mapping, move/Close,
ClientHello output-first driving, input queue admission, cancellation-before-timeout,
retiring queued output at timeout and repeated language-managed drop.

Run scripts/accept.py with a supplied public SDK, sibling net_core checkout and
pinned built OpenSSL tree. See [README](../README.md) for the full command. Output
directories must be new/empty and outside the package. The runner stages package
manifests against SDK precompiled stdlib/kernel and records their hashes. The
source manifests remain unchanged; they use the NyraLang workspace layout.

Certificates and private keys are generated only in the external acceptance
output. They are test fixtures, never user identity material or package assets.
The independent C peer communicates over deliberately fragmented BIO queues;
no public Internet service or private compiler source is involved. The fixture
path ABI is linked only into the test executable.

## Remaining gates

- TCP/Future driving, retained unsent suffixes, partial TCP I/O and loopback TLS streams.
- Full certificate chain/limit/algorithm matrices, tampered records, allocation failures,
  changing read retry arguments, key updates and post-handshake messages.
- Transport-level timeout/cancel and drop/close/reentry behavior under actual I/O.
- Other desktop hosts, mobile builds/runtime, system trust and portable delivery.
- Release CI and public repository origin; this is a local package candidate.

See [the maintained TLS roadmap](../ROADMAP.md). No HTTPS, FIPS, public package
release or complete absence of memory leaks is established by these results.
