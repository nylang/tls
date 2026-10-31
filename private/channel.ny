// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of TlsTransportDriver;

/**
 * @brief Opt-in sequential TLS steps with independent response probes and bounded ciphertext
 *   flushing.
 */

struct TlsChannelData {
  stream: TlsStream;
  failure: TlsStreamError?;
  probe_retry: bool;
  write_retry: bool;
  write_needs_input: bool;
  write_owner: NetBuffer;
}

/**
 * @brief Move-only TCP/TLS owner; caller-thread synchronous steps, no hidden worker or
 *   concurrent calls.
 * @note This separate opt-in API preserves TlsStream's one-pending-Future contract. It can probe
 *   reads while application ciphertext awaits TCP acceptance, provided the provider has no retry
 *   barrier.
 */
pub struct TlsChannel {
  cell: arc<TlsChannelData>?;
}

method(TlsChannelData) Fail(error: TlsStreamError) -> TlsStreamError {
  self.stream.Close();
  self.write_owner = NetBuffer{};
  self.write_retry = false;
  self.probe_retry = false;
  self.failure = error;

  return error;
}

method(TlsChannelData) Check(options: ref NetOperationOptions) -> TlsStreamError? {
  if self.failure != nil {
    return self.failure;
  }

  let check: Result<Unit, NetError> = options.CheckNow();
  if check.IsErr() {
    return self.Fail(TlsStreamError.FromTransport((check.get_if<NetError>()) as NetError));
  }

  if !self.stream.IsOpen() {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  return nil;
}

/**
 * @brief Validate TLS configuration before adopting TCP; failure leaves connection untouched.
 * @returns Ok with TlsChannel on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note Require no outstanding socket I/O/readiness. Zero ciphertext_capacity selects 65536;
 *   explicit capacity must be 32768..1048576, admitting a full 16 KiB record before socket flush.
 *   Peer verification and explicit PEM trust are identical to TlsSession/TlsStream.
 */
pub static method(TlsChannel) NewClient(
  connection: ref mut TcpConnection,
  config: ref TlsClientConfig
) -> Result<TlsChannel, TlsStreamError> {
  var settings: TlsClientConfig = config;
  if settings.ciphertext_capacity == 0 {
    settings.ciphertext_capacity = 65536;
  }

  if settings.ciphertext_capacity < 32768 {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidArgument);
  }

  var made: Result<TlsStream, TlsStreamError> = TlsStream.NewClientWithLimit(
    connection,
    settings,
    16384ip
  );
  if made.IsErr() {
    return (made.get_if<TlsStreamError>()) as TlsStreamError;
  }

  return TlsChannel{cell: new arc<TlsChannelData>{stream: move((made.get_if<TlsStream>()) as TlsStream)}};
}

/**
 * @brief Transfer the sole channel owner.
 * @returns The TlsChannel value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(TlsChannel) operator move() -> TlsChannel {
  let cell: arc<TlsChannelData>? = self.cell;
  self.cell = nil;

  return TlsChannel{cell: cell};
}

/** @brief Retire owned resources on language drop. */
pub method(TlsChannel) operator drop() -> void {
  self.Close();
  self.cell = nil;
}

method(TlsChannelData) DriveOperation(
  queued: Result<AsyncFuture<TlsTransfer>, TlsStreamError>
) -> Result<Unit, TlsStreamError> {
  if queued.IsErr() {
    return (queued.get_if<TlsStreamError>()) as TlsStreamError;
  }

  let future: AsyncFuture<TlsTransfer> = (
    queued.get_if<AsyncFuture<TlsTransfer>>()
  ) as AsyncFuture<TlsTransfer>;
  while !future.is_completed {
    let result: Result<int32, TlsStreamError> = self.stream.Poll(-1);
    if result.IsErr() {
      return self.Fail((result.get_if<TlsStreamError>()) as TlsStreamError);
    }
  }

  let result: Result<TlsTransfer, AsyncError> = future.GetResult();
  if result.IsErr() {
    return self.Fail(TlsStreamError.FromTlsKind(TlsErrorKind.Closed));
  }

  let transfer: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
  if transfer.error != nil {
    return self.Fail(transfer.error as TlsStreamError);
  }

  return Unit{};
}

/**
 * @brief Complete verified handshake and flush its ciphertext using the supplied original
 *   controls.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 */
pub method(TlsChannel) Handshake(options: ref NetOperationOptions) -> Result<Unit, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  if ((s.stream.cell as arc<TlsStreamState>).handshaken) {
    return Unit{};
  }

  return (s).DriveOperation(s.stream.HandshakeAsync(options));
}

/**
 * @brief Owned selected ALPN after handshake, or state/terminal failure.
 * @returns Ok with string on success; Err with TlsStreamError on the failure paths described
 *   above.
 */
pub method(TlsChannel) SelectedAlpn() -> Result<string, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  let s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  if s.failure != nil {
    return s.failure as TlsStreamError;
  }

  return s.stream.SelectedAlpn();
}

// This flush never installs a hidden write-only readiness registration.
method(TlsChannelData) Flush(
  options: ref NetOperationOptions
) -> Result<bool, TlsStreamError> {
  var state: arc<TlsStreamState> = self.stream.cell as arc<TlsStreamState>;
  var rounds: int32 = 0;
  while rounds < 8 {
    let failure: TlsStreamError? = self.Check(options);
    if failure != nil {
      return failure as TlsStreamError;
    }

    rounds = rounds + 1;
    if state.outgoing_start == state.outgoing_count {
      state.outgoing_start = 0ip;
      state.outgoing_count = 0ip;
      if state.session.PendingCiphertext() == (0ip) {
        return true;
      }

      let range: NetMutableBytes = (NetMutableBytes.FromRaw(
        &mut state.outgoing[0],
        16384ip
      ).get_if<NetMutableBytes>()) as NetMutableBytes;
      let drained: Result<intptr, TlsError> = state.session.DrainCiphertext(range);
      if drained.IsErr() {
        return self.Fail(TlsStreamError{tls_error:(drained.get_if<TlsError>()) as TlsError});
      }

      state.outgoing_count = (drained.get_if<intptr>()) as intptr;
    }

    let bytes: NetBytes = (NetBytes.FromRaw(
      &state.outgoing[0],
      state.outgoing_count
    ).get_if<NetBytes>()) as NetBytes;
    let suffix: NetBytes = (bytes.Slice(
      state.outgoing_start,
      state.outgoing_count - state.outgoing_start
    ).get_if<NetBytes>()) as NetBytes;
    let sent: Result<intptr, NetError> = state.connection.TryWrite(suffix);
    let after: TlsStreamError? = self.Check(options);
    if after != nil {
      return after as TlsStreamError;
    }

    if sent.IsErr() {
      let error: NetError = (sent.get_if<NetError>()) as NetError;
      if error.kind == NetErrorKind.WouldBlock {
        return false;
      }

      return self.Fail(TlsStreamError.FromTransport(error));
    }

    let count: intptr = (sent.get_if<intptr>()) as intptr;
    if count <= (0ip) {
      return self.Fail(TlsStreamError.FromTransport(NetError{kind: NetErrorKind.Closed}));
    }

    state.outgoing_start = state.outgoing_start + count;
  }

  return state.outgoing_start == state.outgoing_count && state.session.PendingCiphertext() == (0ip);
}

/**
 * @brief Flush at most eight bounded ciphertext attempts; false means pending output, never
 *   discarded.
 * @returns Ok with bool on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note No application plaintext is accepted here. Failures/controls retire all channel
 *   resources.
 */
pub method(TlsChannel) Flush(options: ref NetOperationOptions) -> Result<bool, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  if ! ((s.stream.cell as arc<TlsStreamState>).handshaken) {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  return (s).Flush(options);
}

/**
 * @brief Accept at most one immutable 16 KiB plaintext block after flushing prior ciphertext.
 * @returns Ok with TlsChannelWrite on success; Err with TlsStreamError on the failure paths
 *   described above.
 * @note Charges entire backing (at most 16 KiB). Zero progress asks for Flush/readiness then
 *   retry with identical bytes; no caller pointer is retained. TLS acceptance does not assert TCP
 *   delivery. NeedRead/NeedWrite require waiting then retrying WriteAvailable with the same block;
 *   RetryRead requires ReadAvailable first. Admission errors leave the active state intact. Report
 *   any positive transfer count before handling its terminal error or parsing an early response.
 */
pub method(TlsChannel) WriteAvailable(
  buffer: ref NetBuffer,
  options: ref NetOperationOptions
) -> Result<TlsChannelWrite, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  var state: arc<TlsStreamState> = s.stream.cell as arc<TlsStreamState>;
  if !state.handshaken || state.peer_closed {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if buffer.RetainedBytes() >(16384ip) {
    return TlsStreamError.FromTlsKind(TlsErrorKind.ResourceExhausted);
  }

  if s.write_retry {
    if buffer.Len() != s.write_owner.Len() {
      return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
    }

    let incoming: NetBytes = buffer.Bytes();
    let retained: NetBytes = s.write_owner.Bytes();
    var i: int32 = 0;
    unsafe {
      while i<(buffer.Len() as int32) {
        if incoming.Data()[i] != retained.Data()[i] {
          return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
        }

        i = i + 1;
      }
    }
  }

  if s.probe_retry {
    return TlsChannelWrite{state: TlsChannelWriteState.RetryRead};
  }

  let flushed: Result<bool, TlsStreamError> = (s).Flush(options);
  if flushed.IsErr() {
    return (flushed.get_if<TlsStreamError>()) as TlsStreamError;
  }

  if ! ((flushed.get_if<bool>()) as bool) {
    return TlsChannelWrite{state: TlsChannelWriteState.NeedWrite};
  }

  if s.write_retry && s.write_needs_input {
    let fed: TlsStreamError? = (state).FeedInput();
    if fed != nil {
      return (s).Fail(fed as TlsStreamError);
    }

    if state.incoming_start == state.incoming_count && !state.input_ended {
      let range: NetMutableBytes = (NetMutableBytes.FromRaw(
        &mut state.incoming[0],
        16384ip
      ).get_if<NetMutableBytes>()) as NetMutableBytes;
      let received: Result<intptr, NetError> = state.connection.TryRead(range);
      if received.IsErr() {
        let error: NetError = (received.get_if<NetError>()) as NetError;
        if error.kind == NetErrorKind.WouldBlock {
          return TlsChannelWrite{state: TlsChannelWriteState.NeedRead};
        }

        return (s).Fail(TlsStreamError.FromTransport(error));
      }

      state.incoming_start = 0ip;
      state.incoming_count = (received.get_if<intptr>()) as intptr;
      if state.incoming_count == (0ip) {
        state.input_eof = true;
      }

      let admitted: TlsStreamError? = (state).FeedInput();
      if admitted != nil {
        return (s).Fail(admitted as TlsStreamError);
      }
    }
  }

  let result: Result<TlsProgress, TlsError> = state.session.WriteStep(buffer.Bytes(), options);
  if result.IsErr() {
    let error: TlsError = (result.get_if<TlsError>()) as TlsError;
    if error.kind == TlsErrorKind.InvalidState {
      return TlsStreamError{tls_error: error};
    }

    return (s).Fail(TlsStreamError{tls_error: error});
  }

  let progress: TlsProgress = (result.get_if<TlsProgress>()) as TlsProgress;
  // This profile reserves an empty >=32 KiB BIO before a <=16 KiB application
  // write. Provider retry barriers are retained; callers retry identical input.
  if progress.state == TlsStepState.PeerClosed {
    return (s).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.UnexpectedEof));
  }

  s.write_retry = progress.state != TlsStepState.Complete;
  s.write_needs_input = progress.state == TlsStepState.NeedInput;
  if s.write_retry {
    s.write_owner = buffer;
  } else {
    s.write_owner = NetBuffer{};
  }

  var next: TlsChannelWriteState = TlsChannelWriteState.Ready;
  if s.write_retry {
    next = TlsChannelWriteState.NeedWrite;
    if s.write_needs_input {
      next = TlsChannelWriteState.NeedRead;
    }
  }

  let count: intptr = progress.bytes_transferred;
  let after: TlsStreamError? = (s).Check(options);

  return TlsChannelWrite{state: next, transfer: TlsTransfer{bytes_transferred: count, error: after}};
}

/**
 * @brief Probe up to 16 KiB plaintext in at most eight nonblocking rounds, without flushing
 *   application output.
 * @returns Ok with TlsChannelRead on success; Err with TlsStreamError on the failure paths
 *   described above.
 * @note NeedRead permits writing; NeedWrite requires flushing output and retrying this read
 *   first. Ready carries owned data or authenticated EOF; errors never manufacture EOF. Partial
 *   native ciphertext stays owned until admitted. Transport/provider failures and controls retire
 *   the channel.
 */
pub method(TlsChannel) ReadAvailable(
  options: ref NetOperationOptions
) -> Result<TlsChannelRead, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  var state: arc<TlsStreamState> = s.stream.cell as arc<TlsStreamState>;
  if !state.handshaken {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if s.write_retry {
    return TlsChannelRead{state: TlsChannelReadState.RetryWrite};
  }

  if state.peer_closed {
    return TlsChannelRead{state: TlsChannelReadState.Ready, transfer: TlsTransfer{eof: true}};
  }

  var rounds: int32 = 0;
  while rounds < 8 {
    rounds = rounds + 1;
    let control: TlsStreamError? = (s).Check(options);
    if control != nil {
      return control as TlsStreamError;
    }

    if s.probe_retry {
      let flushed: Result<bool, TlsStreamError> = (s).Flush(options);
      if flushed.IsErr() {
        return (flushed.get_if<TlsStreamError>()) as TlsStreamError;
      }

      if ! ((flushed.get_if<bool>()) as bool) {
        return TlsChannelRead{state: TlsChannelReadState.NeedWrite};
      }
    }

    let fed: TlsStreamError? = (state).FeedInput();
    if fed != nil {
      return (s).Fail(fed as TlsStreamError);
    }

    let range: NetMutableBytes = (NetMutableBytes.FromRaw(
      &mut state.plaintext[0],
      16384ip
    ).get_if<NetMutableBytes>()) as NetMutableBytes;
    let result: Result<TlsProgress, TlsError> = state.session.ProbeReadStep(range, options);
    if result.IsErr() {
      return (s).Fail(TlsStreamError{tls_error:(result.get_if<TlsError>()) as TlsError});
    }

    let progress: TlsProgress = (result.get_if<TlsProgress>()) as TlsProgress;
    s.probe_retry = progress.state == TlsStepState.NeedOutput;
    if progress.state == TlsStepState.Complete || progress.state == TlsStepState.PeerClosed {
      state.peer_closed = progress.state == TlsStepState.PeerClosed;
      let bytes: NetBytes = (range.AsReadOnly().Slice(
        0ip,
        progress.bytes_transferred
      ).get_if<NetBytes>()) as NetBytes;
      let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
      if copied.IsErr() {
        return TlsChannelRead{
          state: TlsChannelReadState.Ready,
          transfer: TlsTransfer{
            bytes_transferred: progress.bytes_transferred,
            error: (s).Fail(TlsStreamError.FromTransport((copied.get_if<NetError>()) as NetError))
          }
        };
      }

      let after: TlsStreamError? = (s).Check(options);

      return TlsChannelRead{
        state: TlsChannelReadState.Ready,
        transfer: TlsTransfer{
          bytes_transferred: progress.bytes_transferred,
          buffer:(copied.get_if<NetBuffer>()) as NetBuffer,
          eof: state.peer_closed && after == nil,
          error: after
        }
      };
    }

    if s.probe_retry {
      continue;
    }

    if state.incoming_start < state.incoming_count {
      continue;
    }

    if state.input_ended {
      return (s).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.UnexpectedEof));
    }

    let input: NetMutableBytes = (NetMutableBytes.FromRaw(
      &mut state.incoming[0],
      16384ip
    ).get_if<NetMutableBytes>()) as NetMutableBytes;
    let received: Result<intptr, NetError> = state.connection.TryRead(input);
    if received.IsErr() {
      let after: TlsStreamError? = (s).Check(options);
      if after != nil {
        return after as TlsStreamError;
      }

      let error: NetError = (received.get_if<NetError>()) as NetError;
      if error.kind == NetErrorKind.WouldBlock {
        return TlsChannelRead{state: TlsChannelReadState.NeedRead};
      }

      return (s).Fail(TlsStreamError.FromTransport(error));
    }

    state.incoming_start = 0ip;
    state.incoming_count = (received.get_if<intptr>()) as intptr;
    if state.incoming_count == (0ip) {
      state.input_eof = true;
    }
  }

  return TlsChannelRead{state: TlsChannelReadState.Again};
}

/**
 * @brief Wait for either requested direction, without consuming input or borrowing output
 *   storage.
 * @param maximum_wait_ms Zero polls, -1 original controls; nonnegative bounds do not refresh
 *   deadlines.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note One call owns at most two advisory readiness registrations and retires both before
 *   return.
 */
pub method(TlsChannel) Wait(
  readable: bool,
  writable: bool,
  maximum_wait_ms: int32,
  options: ref NetOperationOptions
) -> Result<Unit, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  if maximum_wait_ms < -1 || (!readable && !writable) {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidArgument);
  }

  let state: arc<TlsStreamState> = s.stream.cell as arc<TlsStreamState>;
  var made: Result<NetEventLoop, NetError> = NetEventLoop.New(2);
  if made.IsErr() {
    return (s).Fail(TlsStreamError.FromTransport((made.get_if<NetError>()) as NetError));
  }

  var driver: NetEventLoop = move((made.get_if<NetEventLoop>()) as NetEventLoop);
  var reading: AsyncFuture<Result<Unit, NetError>>? = nil;
  var writing: AsyncFuture<Result<Unit, NetError>>? = nil;
  if readable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = state.connection.WhenReadable(
      driver,
      options
    );
    if registered.IsErr() {
      return (s).Fail(TlsStreamError.FromTransport((registered.get_if<NetError>()) as NetError));
    }

    reading = (
      registered.get_if<AsyncFuture<Result<Unit, NetError>>>()
    ) as AsyncFuture<Result<Unit, NetError>>;
  }

  if writable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = state.connection.WhenWritable(
      driver,
      options
    );
    if registered.IsErr() {
      return (s).Fail(TlsStreamError.FromTransport((registered.get_if<NetError>()) as NetError));
    }

    writing = (
      registered.get_if<AsyncFuture<Result<Unit, NetError>>>()
    ) as AsyncFuture<Result<Unit, NetError>>;
  }

  let polled: Result<int32, NetError> = driver.Poll(maximum_wait_ms);
  let after: TlsStreamError? = (s).Check(options);
  if after != nil {
    return after as TlsStreamError;
  }

  if polled.IsErr() {
    return (s).Fail(TlsStreamError.FromTransport((polled.get_if<NetError>()) as NetError));
  }

  var ready: AsyncFuture<Result<Unit, NetError>>? = nil;
  if reading != nil && (reading as AsyncFuture<Result<Unit, NetError>>).is_completed {
    ready = reading;
  } else if writing != nil && (writing as AsyncFuture<Result<Unit, NetError>>).is_completed {
    ready = writing;
  }

  if ready != nil {
    let result: Result<Result<Unit, NetError>, AsyncError> = (
      ready as AsyncFuture<Result<Unit, NetError>>
    ).GetResult();
    if result.IsErr() {
      return (s).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.Closed));
    }

    let outcome: Result<Unit, NetError> = (result.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
    if outcome.IsErr() {
      return (s).Fail(TlsStreamError.FromTransport((outcome.get_if<NetError>()) as NetError));
    }
  }

  return Unit{};
}

/**
 * @brief Perform bidirectional close_notify after all application output is flushed and no retry
 *   is pending.
 * @returns Ok with Unit on success; Err with TlsStreamError on the failure paths described
 *   above.
 * @note InvalidState leaves the channel intact. Close/drop aborts without flushing remaining
 *   upload.
 */
pub method(TlsChannel) Shutdown(options: ref NetOperationOptions) -> Result<Unit, TlsStreamError> {
  if self.cell == nil {
    return TlsStreamError.FromTlsKind(TlsErrorKind.Closed);
  }

  var s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  let failure: TlsStreamError? = (s).Check(options);
  if failure != nil {
    return failure as TlsStreamError;
  }

  let state: arc<TlsStreamState> = s.stream.cell as arc<TlsStreamState>;
  if s.probe_retry
    || s.write_retry
    || state.session.PendingCiphertext() != (0ip)
    || state.outgoing_start<state.outgoing_count {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  return (s).DriveOperation(s.stream.ShutdownAsync(options));
}

/**
 * @brief Whether the channel owns a live TCP/TLS engine, not a peer-liveness probe.
 * @returns Whether the channel owns a live TCP/TLS engine, not a peer-liveness probe.
 */
pub method(TlsChannel) IsOpen() -> bool {
  if self.cell == nil {
    return false;
  }

  return (self.cell as arc<TlsChannelData>).stream.IsOpen();
}

/** @brief Abort without sending queued upload ciphertext. */
pub method(TlsChannel) Close() -> void {
  if self.cell == nil {
    return;
  }

  let s: arc<TlsChannelData> = self.cell as arc<TlsChannelData>;
  if s.failure == nil {
    let ignored: TlsStreamError = (s).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.Closed));
  }
}
