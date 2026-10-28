# TLS 0.2.0

Source-only release adding authenticated non-reserving read probes and the
optional bounded `TlsChannel` for response-first streamed HTTPS. The existing
`TlsStream` single-pending-Future contract remains unchanged. Explicit PEM CA
trust, DNS/IP identity verification and pinned OpenSSL 3.5.9 LTS remain required.

Published `package.yaml` files retain immutable public Git dependencies. The
source archive preserves those manifests byte for byte; sibling checkout names
and relative dependency rewrites are not required. Git dependency lock/fetch and
locked compilation require corrected Nyra 1.0.4 tools. At preparation time that
SDK is not yet published; the available public SDK 1.0.2 predates Git package
management. This release does not announce SDK 1.0.4 availability. Native OpenSSL
and adapter builds are still separate from Git source acquisition.

The tag pipeline requires four desktop hosts to pass 39 Nyra cases, 39 isolated
replays, 73 native scenarios, production fixture isolation and a moved private
SDK 1.0.2 source consumer. That consumer uses a recorded temporary dependency
overlay solely because SDK 1.0.2 cannot consume Git locks; the overlay is never
included in release assets and is not an end-user Git installation claim.
macOS/Linux bridge/harness acceptance uses ASan/UBSan; Windows is unsanitized.
The complete OpenSSL archive is not claimed to be sanitizer-instrumented.

The release includes source, exact qualification receipts and checksums, with
no precompiled native/provider libraries. Server TLS, mTLS, session resumption,
system trust stores and mobile runtime support are outside this release.
OpenSSL's [3.5 advisory list](https://openssl-library.org/news/vulnerabilities-3.5/)
was reviewed on 2026-10-28; the existing 3.5.9 pin is retained. Historical TLS
0.1.0 tags/assets and their bundled manifests are unchanged.
