# tls

Development API 0.3.0 requires a matching Nyra SDK 1.0.5 or newer.
Rebuild precompiled consumers against the matching interfaces and runtime.

Independent Nyra TLS package, MIT licensed. The initial backend is OpenSSL
3.5 LTS, pinned to **3.5.9** with a verified source archive hash in
[openssl.lock.json](openssl.lock.json). OpenSSL is Apache-2.0 licensed; see
[its retained license](OPENSSL-LICENSE.txt) and [dependency policy](docs/openssl.md).

The package provides a **verified client engine and caller-driven TCP/Future
TLS stream**. It uses net_core's public connection, byte-range, readiness and
control APIs; net_core never imports TLS. HTTP/HTTPS remains a separate package.

**Compiler requirement:** matching Nyra SDK **1.0.5**. Earlier SDKs do not
contain the runtime capabilities used by this working API. The release pipeline
requires exact qualified SDK archive and manifest hashes for all four desktop
hosts; pending pins block qualification and source publication.

- Move-only `TlsSession` owns private native state and releases it through drop.
  Each client has an independent OpenSSL library context and algorithm cache.
- Explicit PEM CA file, mandatory certificate-chain and DNS/IP SAN verification.
  DNS peers use SNI. IP peers verify iPAddress SAN and do not send IP SNI.
- TLS 1.2/1.3 only, no early-data API, compression or renegotiation; optional ALPN.
- Bounded per-direction ciphertext BIO queues; partial admission/draining.
- Handshake/read/write/shutdown steps report input/output needs. A read may need
  output and a write may need input. Always drain output before waiting.
- Up to 16 KiB per plaintext operation. Pending writes retain a private copy;
  retries must have identical data/length. No caller buffer pointer is retained.
- Absolute net_core deadlines and cancellation checks on every protocol step;
  cancellation wins over timeout and retires the engine.
- Authenticated `close_notify` is distinct from unexpected transport EOF.
- Peer TLS 1.3 key updates preserve bidirectional traffic under partial transport
  progress; altered/replayed records fail without publishing unauthenticated plaintext.
- `TlsStream` moves TCP ownership on successful construction and owns one bounded
  readiness driver. `HandshakeAsync`, `ReadAsync`, `WriteAllAsync` and
  `ShutdownAsync` return local Futures driven explicitly by `Poll`.
- Partial TCP sends retain unsent ciphertext offsets; oversized input fragments
  remain buffered until BIO admission. Readiness uses the original operation
  deadline/token. One pending operation and a configurable payload limit bound
  retained work; Close/drop retires all resources before publishing completion.

The public faces are [engine](interface/tls.ni) and [stream](interface/stream.ni).
See [stream driving/ownership](docs/stream.md) and
[engine contracts and transport driving](docs/engine.md) before using it.
A step's Complete state may still leave output to send. Ciphertext removed by
DrainCiphertext becomes the transport driver's responsibility: retain unsent
suffixes across partial TCP writes. Do not read more ciphertext than can be
retained when FeedCiphertext admits only part of a buffer.

## Source distribution

[TLS 0.1.0](https://github.com/nylang/tls/releases/tag/v0.1.0) provides
`tls-0.1.0-source.tar.gz` with sibling `tls` and
`net_core` packages, dependency locks and acceptance receipts. Its prepared
manifests resolve stdlib from the installed SDK and net_core through
`../net_core`. Keep those sibling directories together. Build the pinned
OpenSSL libraries and native adapters with the supplied scripts before linking
an application. The archive contains source only; native provider binaries and
precompiled Nyra TLS libraries are built locally.

The existing v0.1.0 tag/archive retain their original manifests and acceptance
identities. The current main checkout uses implicit SDK stdlib and a fixed public
net_core Git dependency instead of publisher-local dependency paths. GitHub's
automatic archives follow the selected commit; they do not bundle Git dependencies.
Distribution details and host limitations for the historical release are recorded in
[the release notes](docs/release-0.1.0.md),
[publication receipt](docs/publication-0.1.0.json) and the archive's `release.json`.

## Build and verify

Build tools require Python 3.12+, Perl, Make and a host C compiler. Windows uses
native Strawberry Perl and an x64 Visual Studio Developer Command Prompt with
NMake; the initial Windows provider build disables assembly. All generated
outputs must be outside this package. An explicitly selected matching Nyra SDK 1.0.5,
sibling net_core checkout and OpenSSL CLI 3.5+ are needed for full acceptance.
Use `--build-cli` to build that CLI from the same checksum-pinned provider source;
acceptance selects it automatically when present. `--openssl-cli` selects an
explicit alternative for test certificates.
The CLI generates only temporary test certificates; the bridge always links the
pinned 3.5.9 static libraries.

```sh
python3 scripts/build_openssl.py --out-dir /absolute/cache/openssl-build --build-cli
python3 scripts/accept.py \
  --sdk /absolute/path/to/nyra-sdk \
  --net-core /absolute/path/to/net_core \
  --openssl-root /absolute/cache/openssl-build/openssl-3.5.9 \
  --out-dir /absolute/cache/tls-acceptance
```

The acceptance runner stages both Nyra packages against SDK precompiled stdlib
with source fallback disabled. It runs native behavior cases, Nyra ownership/
control cases, isolated replays and production fixture-import checks. On macOS,
use a host Clang with a compatible ASan runtime (for example
`--native-cc /usr/bin/clang`); the selected native compiler uses the supplied SDK runtime.
The SDK 1.0.0 bundled Clang 21 ASan runtime stalls during initialization on the
accepted macOS 27 host, so it is not used for sanitized native acceptance.

For native-only checks:

```sh
python3 scripts/accept_native.py \
  --openssl-root /absolute/cache/openssl-build/openssl-3.5.9 \
  --out-dir /absolute/cache/tls-native --sanitize
```

On Windows run the same scripts with native Python in the developer prompt,
pass `--perl` to the provider builder when Perl is outside PATH, and use
`--no-sanitize` for the full acceptance run if the selected C toolchain has no
compatible ASan/UBSan runtime. Receipts record this omission; an unsanitized
Windows result does not establish sanitizer coverage.

Applications link `libtls_native.a`, the matching `libssl.a`/`libcrypto.a`
(`libssl.lib`/`libcrypto.lib` for the MSVC provider build),
net_core's native library and Nyra's platform runtime. POSIX may also need
`-lpthread`/`-ldl`. Windows also needs OpenSSL's `ws2_32`, `gdi32`, `advapi32`,
`crypt32` and `user32`, plus net_core's `iphlpapi` system library.
No OpenSSL pointers or private bridge ABI are exported from
`tls.ny`. Current repository manifests use public Git dependencies and implicit
SDK runtimes; the historical v0.1.0 source asset retains its bundled manifests.
Precompiled multitarget package delivery remains outside this source release.

[Acceptance and retained receipt](tests/README.md); [remaining roadmap](ROADMAP.md).

## Portable Git dependency

This working API requires matching Nyra SDK 1.0.5 compiler, runtime and analyzer
capabilities. Its manifest uses implicit SDK packages and contains no paths into
the private compiler checkout. Use the SDK's native `nyra` for Git preparation.
Older source tags retain their documented SDK requirements; they do not qualify
this development API. SDK/package publication remains a separate operation.

Add this dependency to your application's `package.yaml`:

```yaml
dependencies:
  tls:
    git: https://github.com/nylang/tls.git
    rev: d8a70247fefb303738d082b9461a9a23b50ce67b
```

Run `nyra lock ./app` and commit `nyra.lock`; use
`nyra fetch ./app --frozen` to prepare the same graph again. The example pins
an existing public development commit whose API matches this source. It does
not select the older stable `main` or claim a newly published package tag.
Normal compiler and analyzer operations do not fetch dependencies.

For local multi-package development, list package-file pointers in a common
`workspace.yaml`. Workspace replacements keep Git declarations shareable;
origin lock updates deliberately disable replacements. A package entry and its
SDK can move without rewriting publisher paths.


## Local development: response-first TLS channel

The working tree adds `TlsSession.ProbeReadStep` and the optional `TlsChannel`
for streamed HTTP consumers. These additions are not part of the immutable
published 0.1.0 source receipt. Existing `ReadStep` still reserves a pending read,
and `TlsStream` still permits one pending Future. No public ABI layout, trust
policy, provider pin, socket ownership or retry rule of those APIs is replaced.

`ProbeReadStep` requires a borrowed 16384-byte output range. It uses stable
engine-owned retry storage and only copies authenticated returned bytes into the
caller range. NeedInput leaves no read reservation, including for an incomplete
TLS record; queued outbound ciphertext remains untouched. Actual provider
WANT_WRITE reserves this probe until output is drained and the same probe is
retried. Ordinary pending reads/writes reject probing. Raw EOF and authentication
failure remain terminal failures, never a successful empty read.

The probe follows the provider's [nonblocking I/O rules](https://docs.openssl.org/3.5/man3/SSL_get_error/).
Read and write retry barriers remain distinct from socket readiness. In particular,
a pending provider write cannot be replaced by a read simply because a socket is
readable. The optional channel preserves these barriers and exposes advisory
read/write states rather than pretending every operation is interchangeable.

`TlsChannel.NewClient` validates before adopting TCP, retaining explicit PEM
trust, peer verification and ALPN. Zero BIO capacity selects 65536; explicit
capacity must be 32768..1048576. It admits at most one 16 KiB immutable plaintext
block after prior ciphertext drains, enough for a complete application record in
this TLS 1.2/1.3 client profile. TLS acceptance and TCP delivery are different:
`WriteAvailable` reports accepted plaintext before socket flushing. Preserve its
positive count before handling a terminal error. Provider retries require the
same immutable bytes; no caller pointer is retained.

`ReadAvailable` performs at most eight nonblocking rounds and can decrypt a peer
response while accepted application ciphertext awaits socket writability.
NeedRead permits writing, NeedWrite reserves a read retry, and RetryWrite requires
retrying the original write. `Flush` preserves every unsent ciphertext suffix.
`Wait` owns at most two readiness-only registrations and retires both before
return; all methods stay on the caller thread. The caller carries the same
absolute deadline/shared cancellation through every method. Admission rejection
is nonterminal; operational failures retire TCP/TLS and preserve the first cause.

`Shutdown` requires no pending output/provider retry; it then drives the existing
verified close-notify mechanism. `Close`/drop never flushes pending application
ciphertext. That distinction lets an HTTP consumer stop an upload after an early
final response without sending another accepted-but-unsent TLS record solely to
start graceful shutdown. Returned plaintext owners survive channel retirement.


[Channel acceptance](docs/channel-acceptance-2026-10-28.json) records 39 TLS
cases/replays and 73 native cases on macOS arm64, Linux x86_64 and Windows x86_64
with matching SDK 1.0.2 compiler/runtime inputs. Seven new channel cases and one
probe-control case extend the previous 31; thirteen probe/KeyUpdate native cases
extend the previous 60. Each host also passes the full streamed HTTPS regression.
Intel macOS is pending authorized SSH recovery, so the overall desktop matrix
remains partial. These records retain their exact source snapshot and do not
change the published 0.1.0 acceptance or claim complete provider-state/fault coverage.

## Published 0.2.0

[tls 0.2.0](https://github.com/nylang/tls/releases/tag/v0.2.0) is a source-only release. Its package.yaml
retains immutable public Git dependencies; the source assets preserve the
original declarations without relative sibling rewrites. Corrected Nyra 1.0.4
tools are required for locked Git consumption; that SDK is not yet publicly
released. The HTTP release's [Git consumer evidence](https://github.com/nylang/http/releases/download/v0.1.0/git-consumer-acceptance.json) includes this TLS revision and has passed lock/fetch, relocation/offline,
semantic checking, native linking and execution with the source tool candidate.
Protocol qualification with public SDK 1.0.2 is recorded separately.

See the [publication receipt](docs/publication-0.2.0.json) for exact
sources, assets and native desktop qualification. Historical development
receipts retain their original pending/partial state and are not rewritten.

## Module architecture

See [module responsibilities, ownership and dependency boundaries](ARCHITECTURE.md).

## Coding-rule lint

`package.yaml` selects the portable `lint.yaml` profile. It requires the
1.0.5 P7 analyzer candidate (or a later SDK containing those rules); the
published 1.0.4 analyzer does not implement them. `import: default` inherits
the selected workspace profile when present, otherwise analyzer SDK defaults.
No sibling source path is required. Run `nyra-analyzer lint . --json`. Lint checks
coding rules; runtime qualification is a separate gate.
