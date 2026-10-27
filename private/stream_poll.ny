/** @brief Bounded socket/protocol pumping with preserved ciphertext suffixes. */
part of TlsEngine;

func tls_stream_flush(cell: arc<TlsStreamState>) -> Result<bool, TlsStreamError> {
  var state: arc<TlsStreamState> = cell;
  if state.outgoing_start == state.outgoing_count {
    state.outgoing_start = 0 as intptr; state.outgoing_count = 0 as intptr;
    if state.session.PendingCiphertext() > (0 as intptr) {
      let writable: NetMutableBytes = (NetMutableBytes.FromRaw(&mut state.outgoing[0], 16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
      let drained: Result<intptr, TlsError> = state.session.DrainCiphertext(writable);
      let error: TlsError? = drained.get_if<TlsError>();
      if error != nil { return TlsStreamError{tls_error: error}; }
      state.outgoing_count = (drained.get_if<intptr>()) as intptr;
    }
  }
  if state.outgoing_start < state.outgoing_count {
    let bytes: NetBytes = (NetBytes.FromRaw(&state.outgoing[0], state.outgoing_count).get_if<NetBytes>()) as NetBytes;
    let suffix: NetBytes = (bytes.Slice(state.outgoing_start, state.outgoing_count - state.outgoing_start).get_if<NetBytes>()) as NetBytes;
    let sent: Result<intptr, NetError> = state.connection.TryWrite(suffix);
    let failure: NetError? = sent.get_if<NetError>();
    if failure != nil {
      let error: NetError = failure as NetError;
      if error.kind != NetErrorKind.WouldBlock { return tls_stream_transport_error(error); }
      let registered: TlsStreamError? = tls_stream_register(state, true);
      if registered != nil { return registered as TlsStreamError; }
      return false;
    }
    let count: intptr = (sent.get_if<intptr>()) as intptr;
    if count <= (0 as intptr) { return TlsStreamError{transport_error: NetError{kind: NetErrorKind.Closed}}; }
    state.outgoing_start = state.outgoing_start + count;
  }
  return state.outgoing_start == state.outgoing_count && state.session.PendingCiphertext() == (0 as intptr);
}
func tls_stream_feed(cell: arc<TlsStreamState>) -> TlsStreamError? {
  var state: arc<TlsStreamState> = cell;
  if state.incoming_start < state.incoming_count {
    let bytes: NetBytes = (NetBytes.FromRaw(&state.incoming[0], state.incoming_count).get_if<NetBytes>()) as NetBytes;
    let suffix: NetBytes = (bytes.Slice(state.incoming_start, state.incoming_count - state.incoming_start).get_if<NetBytes>()) as NetBytes;
    let fed: Result<intptr, TlsError> = state.session.FeedCiphertext(suffix);
    let error: TlsError? = fed.get_if<TlsError>();
    if error != nil { return TlsStreamError{tls_error: error}; }
    state.incoming_start = state.incoming_start + ((fed.get_if<intptr>()) as intptr);
  }
  if state.incoming_start == state.incoming_count {
    state.incoming_start = 0 as intptr; state.incoming_count = 0 as intptr;
    if state.input_eof && !state.input_ended {
      let ended: Result<Unit, TlsError> = state.session.EndInput();
      let error: TlsError? = ended.get_if<TlsError>();
      if error != nil { return TlsStreamError{tls_error: error}; }
      state.input_ended = true;
    }
  }
  return nil;
}
func tls_stream_protocol(cell: arc<TlsStreamState>) -> Result<TlsProgress, TlsError> {
  var state: arc<TlsStreamState> = cell;
  if state.operation == TlsStreamOperation.Handshake {
    return state.session.HandshakeStep(state.options);
  }
  if state.operation == TlsStreamOperation.Shutdown {
    return state.session.ShutdownStep(state.options);
  }
  if state.operation == TlsStreamOperation.Read {
    let buffer: NetMutableBytes = (NetMutableBytes.FromRaw(&mut state.plaintext[0], state.read_capacity as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
    return state.session.ReadStep(buffer, state.options);
  }
  let remaining: intptr = state.input.Len() - state.progress;
  var size: intptr = remaining;
  if size > (16384 as intptr) { size = 16384 as intptr; }
  let bytes: NetBytes = state.input.Bytes();
  let chunk: NetBytes = (bytes.Slice(state.progress, size).get_if<NetBytes>()) as NetBytes;
  return state.session.WriteStep(chunk, state.options);
}
/** @brief Drive bounded rounds and retire all state before publishing any operation result. */
pub method(TlsStream) Poll(maximum_wait_ms: int32) -> Result<int32, TlsStreamError> {
  if maximum_wait_ms < -1 { return tls_stream_error(TlsErrorKind.InvalidArgument); }
  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil { return 0; }
  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.driving { return tls_stream_error(TlsErrorKind.InvalidState); }
  if state.closed || state.operation == TlsStreamOperation.Idle { return 0; }
  state.driving = true;
  var rounds: int32 = 0;
  while rounds < 8 {
    rounds = rounds + 1;
    let control: TlsStreamError? = tls_stream_control(state);
    if control != nil { return tls_stream_fail(state, control as TlsStreamError); }
    let pending: AsyncFuture<Result<Unit, NetError>>? = state.wait;
    if pending != nil {
      let waiting: AsyncFuture<Result<Unit, NetError>> = pending as AsyncFuture<Result<Unit, NetError>>;
      if !waiting.is_completed {
        let polled: Result<int32, NetError> = state.driver.Poll(maximum_wait_ms);
        let poll_error: NetError? = polled.get_if<NetError>();
        // Controls precede a simultaneous native readiness/error result.
        let after_wait: TlsStreamError? = tls_stream_control(state);
        if after_wait != nil { return tls_stream_fail(state, after_wait as TlsStreamError); }
        if poll_error != nil { return tls_stream_fail(state, tls_stream_transport_error(poll_error as NetError)); }
        if !waiting.is_completed { state.driving = false; return 0; }
      }
      state.wait = nil;
      let completed: Result<Result<Unit, NetError>, AsyncError> = waiting.GetResult();
      if completed.IsErr() { return tls_stream_fail(state, tls_stream_error(TlsErrorKind.Closed)); }
      let ready: Result<Unit, NetError> = (completed.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
      let ready_error: NetError? = ready.get_if<NetError>();
      if ready_error != nil { return tls_stream_fail(state, tls_stream_transport_error(ready_error as NetError)); }
    }
    let flushed: Result<bool, TlsStreamError> = tls_stream_flush(state);
    // Final socket progress must not publish success or an error ahead of controls.
    let after_flush: TlsStreamError? = tls_stream_control(state);
    if after_flush != nil { return tls_stream_fail(state, after_flush as TlsStreamError); }
    let flush_error: TlsStreamError? = flushed.get_if<TlsStreamError>();
    if flush_error != nil { return tls_stream_fail(state, flush_error as TlsStreamError); }
    if !((flushed.get_if<bool>()) as bool) {
      if state.wait != nil { state.driving = false; return 0; }
      continue;
    }
    if state.operation_done {
      return tls_stream_finish(state, nil, state.operation == TlsStreamOperation.Shutdown);
    }
    if state.operation == TlsStreamOperation.Write && state.progress == state.input.Len() {
      state.operation_done = true; continue;
    }
    if state.operation == TlsStreamOperation.Read && (state.read_capacity == 0 || state.peer_closed) {
      state.operation_eof = state.read_capacity != 0 && state.peer_closed;
      state.operation_done = true; continue;
    }
    let feed_error: TlsStreamError? = tls_stream_feed(state);
    if feed_error != nil { return tls_stream_fail(state, feed_error as TlsStreamError); }
    let stepped: Result<TlsProgress, TlsError> = tls_stream_protocol(state);
    let protocol_error: TlsError? = stepped.get_if<TlsError>();
    if protocol_error != nil { return tls_stream_fail(state, TlsStreamError{tls_error: protocol_error}); }
    let progress: TlsProgress = (stepped.get_if<TlsProgress>()) as TlsProgress;
    if progress.state == TlsStepState.PeerClosed && state.operation != TlsStreamOperation.Read {
      return tls_stream_fail(state, tls_stream_error(TlsErrorKind.UnexpectedEof));
    }
    if progress.state == TlsStepState.Complete || progress.state == TlsStepState.PeerClosed {
      if state.operation == TlsStreamOperation.Handshake { state.handshaken = true; state.operation_done = true; }
      else if state.operation == TlsStreamOperation.Write {
        state.progress = state.progress + progress.bytes_transferred;
        state.operation_done = state.progress == state.input.Len();
      } else if state.operation == TlsStreamOperation.Read {
        state.progress = progress.bytes_transferred;
        state.operation_eof = progress.state == TlsStepState.PeerClosed;
        if state.operation_eof { state.peer_closed = true; }
        let bytes: NetBytes = (NetBytes.FromRaw(&state.plaintext[0], state.progress).get_if<NetBytes>()) as NetBytes;
        let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
        let copy_error: NetError? = copied.get_if<NetError>();
        if copy_error != nil { return tls_stream_fail(state, tls_stream_transport_error(copy_error as NetError)); }
        state.result_buffer = (copied.get_if<NetBuffer>()) as NetBuffer;
        state.operation_done = true;
      } else { state.operation_done = true; }
      continue;
    }
    if progress.state == TlsStepState.NeedOutput || state.session.PendingCiphertext() > (0 as intptr) { continue; }
    if state.incoming_start < state.incoming_count { continue; }
    if state.input_ended { return tls_stream_fail(state, tls_stream_error(TlsErrorKind.UnexpectedEof)); }
    let input: NetMutableBytes = (NetMutableBytes.FromRaw(&mut state.incoming[0], 16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
    let received: Result<intptr, NetError> = state.connection.TryRead(input);
    let receive_error: NetError? = received.get_if<NetError>();
    if receive_error != nil {
      let error: NetError = receive_error as NetError;
      if error.kind != NetErrorKind.WouldBlock { return tls_stream_fail(state, tls_stream_transport_error(error)); }
      let registered: TlsStreamError? = tls_stream_register(state, false);
      if registered != nil { return tls_stream_fail(state, registered as TlsStreamError); }
      state.driving = false; return 0;
    }
    state.incoming_start = 0 as intptr;
    state.incoming_count = (received.get_if<intptr>()) as intptr;
    if state.incoming_count == (0 as intptr) { state.input_eof = true; }
  }
  state.driving = false;
  return 0;
}
