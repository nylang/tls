# Caller-driven TCP/TLS stream

TlsStream owns a move-only TcpConnection, TlsSession and a one-registration
NetEventLoop. There is no background executor, TLS worker or private access to
net_core descriptors. NewClient constructs the engine and driver first, then
moves the supplied connection only on success. An invalid configuration leaves
the caller's socket unchanged. The socket must have no outstanding operations
or registrations before transfer and must not be used outside the stream after it.

## Futures, affinity and admission

HandshakeAsync, ReadAsync, WriteAllAsync and ShutdownAsync return local
AsyncFuture<TlsTransfer>. Only one operation may be pending per stream. Poll
advances up to eight bounded protocol/transport rounds and performs at most one
native wait. Poll(-1) may wait under the pending operation's absolute controls;
Poll(0) does no waiting. Idle Poll returns immediately. These methods, Close and
Future access remain on the same caller thread. A retained NetCancellation token
may be cancelled on another thread under net_core's contract.

Dropping a Future does not cancel the operation: the stream still owns it.
Moving a stream transfers pending work. Close/drop retires the driver, duplicated
registrations, TCP and TLS engine before completing outstanding work with Closed.
State, retained backing, promise and driving guard are detached before callbacks.
Successful callbacks may enqueue and Poll new work or Close/move the stream;
the original Poll does not overwrite callback state changes after publication.

Admission validates state, payload budget and controls. Rejection returns the
outer Result and leaves the existing stream/operation intact. Once admitted,
TLS/transport failure, cancellation or timeout retires the stream and returns the
error in TlsTransfer. Cancellation takes priority over timeout, including after
a native wait. Poll also rechecks controls immediately after a transport flush,
before reporting either its native error or operation success. This covers a token
cancelled or a deadline reached while the final ciphertext write is returning;
TLS-accepted plaintext progress remains in the terminal transfer. These observation
points do not promise atomic scheduling of cancellation and Future publication.
No per-retry timeout is started. Wakeable tokens interrupt native waits directly;
flag-only tokens retain net_core's documented cooperative bound.

Explicit Close completes admitted work with Closed immediately, even if its token
was cancelled but Poll has not yet processed it. A completed Future is immutable:
cancelling from its completion callback cannot replace its published result.

## Queues, retries and progress

The stream retains 16 KiB input/output/plaintext scratch ranges in addition to
the engine's bounded BIO/retry storage. Ciphertext removed from the BIO retains
its unsent offset until TryWrite accepts it. WouldBlock registers write readiness
without discarding/replaying accepted bytes. Pending generated output is drained
before waiting for more input, even when the TLS operation is a read or shutdown.
TLS requests, not plaintext operation names, determine the readiness direction.

TryRead only fills stream-owned storage. FeedCiphertext consumes a prefix within
its quota; the suffix is retained and fed after protocol processing frees space.
No next socket read overwrites a retained suffix. Transport FIN is marked on the
engine only after preceding bytes are admitted. Owned received plaintext is copied
into immutable NetBuffer storage before Future publication.

WriteAllAsync retains the complete immutable NetBuffer backing and processes
stable 16 KiB plaintext chunks. The caller's original value may drop immediately.
A pending TLS write retries identical bytes/length; the committed plaintext offset
advances only after engine acceptance. Failure retains that prefix count and
retirements release all pending backing. TLS-accepted bytes are not remote
acknowledgements; a failure during ciphertext flushing can leave those bytes
partially transmitted. Do not replay them as a new TLS operation automatically.

The default pending-payload limit is one MiB. Writes charge root backing size,
not slice length; reads reserve requested size (0..16384). A zero limit still
permits handshake, shutdown and empty I/O. Fixed scratch/BIO/Future overhead and
consumer-held completed buffers are outside this pending-byte budget.

## EOF and shutdown

A positive-sized read returns eof only on verified close_notify. That peer EOF
is sticky for subsequent nonempty reads; empty reads remain no-ops with eof=false.
Plaintext writes are rejected after peer EOF; orderly shutdown can still send
our close_notify. Raw FIN without close_notify returns UnexpectedEof and retires
the stream. Already published plaintext buffers remain owned by their consumers.

ShutdownAsync requires a completed handshake and no other pending operation.
Success requires both TLS close notifications and flushing all outbound bytes;
it retires TCP/TLS before completing. Sending only our alert is not success:
the original deadline/cancellation also bounds waiting for the peer. Close/drop
performs abrupt local cleanup without protocol I/O.

## Compiler and acceptance boundaries

The integration exposed a native Core ownership defect: ExclusiveStorage ignored
an explicit deleted copy on a facade containing ARC. Result extraction cloned
that owner and temporary cleanup closed the returned stream. The source fix
honors the existing deleted-copy contract; no language/API workaround is used.
Published SDK 1.0.0/1.0.1 compilers lack the fix. scripts/accept.py accepts
--compiler for an explicit native source candidate while preserving a separately
verified public SDK runtime/manifest identity and disabling source fallback.
macOS deployment target follows the chosen runtime manifest.

The [control-boundary acceptance](control-boundary-acceptance-2026-10-27.json)
adds eight cases: final-flush cancel, timeout and cancellation-over-timeout;
cancellation-over-send-error; cancel after native ciphertext read; cancel while
shutdown awaits the peer; explicit Close of a cancelled partial write; and shutdown
callback reentry with late cancellation. Test-only interposition rendezvous lets a
worker publish controls before native I/O returns. The worker never accesses a
TlsStream. Deadline tests wait for the absolute time after reaching the rendezvous;
reaching it and releasing it before its guard timeout are both asserted.

[Acceptance](../tests/README.md) retains the historical three-host source-candidate
coverage and describes the separate four-host public-SDK release gates. Broader
transition/allocation matrices and mobile runtime acceptance remain open.
