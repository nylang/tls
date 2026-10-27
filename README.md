# tls

Independent Nyra TLS package, MIT licensed. The initial backend is OpenSSL
3.5 LTS, pinned to **3.5.9** with a verified source archive hash in
[openssl.lock.json](openssl.lock.json). OpenSSL is Apache-2.0 licensed; see
[its retained license](OPENSSL-LICENSE.txt) and [dependency policy](docs/openssl.md).

The package provides a **verified client engine and caller-driven TCP/Future
TLS stream**. It uses net_core's public connection, byte-range, readiness and
control APIs; net_core never imports TLS. HTTP/HTTPS remains a separate package.

**Compiler requirement:** the stream needs the native deleted-copy ARC ownership
fix discovered during integration. Published SDK 1.0.0/1.0.1 compilers contain the
defect; use an explicit compatible source candidate with the public SDK runtime
until a fixed SDK is accepted. No SDK promotion is implied by local TLS acceptance.

- Move-only `TlsSession` owns private native state and releases it through drop.
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

## Build and verify

Build tools require Python 3.12+, Perl, Make and a host C compiler. All generated
outputs must be outside this package. An explicitly selected public Nyra SDK,
sibling net_core checkout and OpenSSL CLI 3.5+ are needed for full acceptance.
The CLI generates only temporary test certificates; the bridge always links the
pinned 3.5.9 static libraries.

```sh
python3 scripts/build_openssl.py --out-dir /absolute/cache/openssl-build
python3 scripts/accept.py \
  --sdk /absolute/path/to/nyra-sdk \
  --compiler /absolute/path/to/compatible/nyrac \
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

Applications link `libtls_native.a`, the matching `libssl.a`/`libcrypto.a`,
net_core's native library and Nyra's platform runtime. POSIX may also need
`-pthread`/`-ldl`. No OpenSSL pointers or private bridge ABI are exported from
`tls.ny`. Source manifests use the NyraLang workspace dependency layout; portable
package distribution and other-host acceptance remain open.

[Acceptance and retained receipt](tests/README.md); [remaining roadmap](ROADMAP.md).
