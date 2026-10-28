# TLS 0.1.0

Independent MIT-licensed Nyra TLS client engine and caller-driven TCP/Future
stream adapter, using pinned OpenSSL 3.5.9 LTS. Requires Nyra SDK 1.0.2 and the
locked net_core dependency. Explicit PEM CA trust and DNS/IP SAN verification
are mandatory. There is no verification-disable option or implicit system trust.

This is a source-only release. The source distribution includes sibling tls and
net_core packages, prepared relocatable manifests, dependency locks, build tools,
licenses and exact acceptance receipts. It includes no SDK/compiler internals,
provider binaries or precompiled TLS libraries. Build the pinned OpenSSL static
libraries and ordinary native adapters using the supplied scripts. Bundled
manifests resolve stdlib from the installed SDK; their implementation sources
are unchanged from the recorded commits. GitHub's automatic source archives
contain only the TLS repository and retain its source-workspace manifest layout.

The tag pipeline requires all four desktop host jobs to pass against the exact
checksum-pinned public SDK before publishing: 31 Nyra cases, 31 isolated replays,
60 native behavior/resource scenarios, production fixture isolation and a moved
source consumer. macOS/Linux native harnesses use ASan/UBSan; Windows explicitly
records unsanitized native acceptance. OpenSSL static libraries themselves are
not claimed to be sanitizer-instrumented. Consult release.json/evidence for exact
source, SDK, provider and runtime identities, tested OS versions and limitations.
The source archive, release.json and SHA256SUMS are the release assets.

The engine supports TLS 1.2/1.3, verified client handshake, bounded BIO queues,
partial progress, key updates and authenticated close_notify. Streams retain
absolute deadlines/shared cancellation, retire on terminal errors and preserve
accepted plaintext progress. Provider contexts are isolated per client to keep
allocation failure from poisoning later sessions. No server/mTLS/session
resumption, platform CA-store integration, HTTP client or mobile runtime support
is advertised. SDK code signing/notarization is separate; no new signing
attestation is supplied by this source release.
