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
