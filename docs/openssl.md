# OpenSSL dependency policy

The user selected OpenSSL on 2026-10-27. The initial backend is **3.5 LTS**,
pinned to **3.5.9** by URL and SHA-256 in openssl.lock.json. The
[official release list](https://openssl-library.org/source/) identifies this
branch's support through 2030-04-08. The private bridge rejects other header or
runtime versions instead of silently linking an unaccepted system library.

scripts/build_openssl.py verifies the release archive checksum before extracting
it into an external cache, and builds host static libraries. It does not modify
the system OpenSSL installation. It records commands and archive/library hashes.
The upstream OpenSSL test suite is not run by that script; package acceptance
covers the bridge and its documented cases only.

OpenSSL is Apache-2.0 licensed; this package's own source is MIT. Retain
OPENSSL-LICENSE.txt with redistributed OpenSSL libraries or statically linked
products, along with this package's MIT license and any additional upstream
notices required by the chosen distribution. The native builder copies both
licenses into its output directory. No FIPS validation is claimed.

Before any public package release, check upstream security advisories and support
status. On a relevant advisory or supported patch update, revise the pin explicitly,
verify its official digest, rebuild all advertised target libraries, rerun
negative certificate/identity/protocol cases plus transport/platform acceptance,
and record new source/library/compiler identities. Do not accept arbitrary
system-library substitution or silently advance a dependency in release builds.
Provider replacement must preserve the public face and pass the same acceptance.

System trust is a separate platform concern. This increment supports explicit PEM
CA configuration only. It does not claim macOS Keychain, Windows certificate-store
or mobile platform trust integration. HTTPS remains unavailable until the TLS
transport and separate HTTP package are accepted.
