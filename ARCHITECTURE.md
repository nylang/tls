# tls module architecture

The TLS engine and the network record driver are independent TUs. Public session,
stream and channel faces retain their existing ownership and retry contracts.

- `private/tls.ny` owns the native engine handle, C ABI error mapping, bounded
  feed/drain operations and cryptographic operation progress. It does not own a
  socket, network readiness queue or DNS resolver.
- `private/stream.ny` with `stream_poll.ny` and `channel.ny` owns a TLS connection's
  TCP socket, encrypted/plaintext buffers, readiness registration and retry barriers.
  Stream and Channel are two operation policies over this same record driver;
  their parts intentionally remain one TU so buffer/retry layouts stay private.
- `tests/suite_selftest.ny` owns independent session, stream, control and channel
  contract tests. It imports product faces and implementations without joining the
  production connection TU.

The record driver calls session operations and net_core product operations. The
session engine never calls the network driver. No engine handle or record-driver
state layout is exported to a new product face. OpenSSL and the platform backend
retain their existing native compilation and licensing boundaries.


## 1.0.5 implementation ownership

TlsNativeResult projects native completion status; TlsError owns native error
conversion and TlsStreamError preserves TLS/transport causes and control
precedence. TlsSession owns engine stepping. TlsStreamState owns record progress,
buffer/retry state, readiness, admission, retirement and promise publication.
TlsChannelData owns the channel policy over the same private record-driver TU.
Methods borrow that state while caller ARC values retain its lifetime; no new
native owner is created. Completion detaches mutable operation state before
publishing a continuation, preserving reentrant Close/Poll behavior.

Test-only constructors, transfer checks and bounded pumps are extensions on the
corresponding value/resource owners. Immutable echo/control cases retain their
input matrix; spawned workers copy their control values rather than capturing a
borrowed case receiver. Shared ntest assertions replace the local counter wrapper.
Function scopes intentionally exercising return-time Drop/Future release retain
individual lint reasons. Native bridge symbols and public TLS APIs are unchanged.
Focused source acceptance is distinct from independent publication or SDK release.
