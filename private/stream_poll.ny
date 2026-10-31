// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of TlsTransportDriver;

/** @brief Bounded socket/protocol pumping with preserved ciphertext suffixes. */

// Keep unsent ciphertext prefixes across short writes; retrying must not replay bytes already accepted by TCP.
method(TlsStreamState) FlushOutput() -> Result<bool, TlsStreamError> {
  if self.outgoing_start == self.outgoing_count {
    self.outgoing_start = 0ip;
    self.outgoing_count = 0ip;
    if self.session.PendingCiphertext() >(0ip) {
      let writable: NetMutableBytes = (NetMutableBytes.FromRaw(
        &mut self.outgoing[0],
        16384ip
      ).get_if<NetMutableBytes>()) as NetMutableBytes;
      let drained: Result<intptr, TlsError> = self.session.DrainCiphertext(writable);
      let error: TlsError? = drained.get_if<TlsError>();
      if error != nil {
        return TlsStreamError{tls_error: error};
      }

      self.outgoing_count = (drained.get_if<intptr>()) as intptr;
    }
  }

  if self.outgoing_start < self.outgoing_count {
    let bytes: NetBytes = (NetBytes.FromRaw(
      &self.outgoing[0],
      self.outgoing_count
    ).get_if<NetBytes>()) as NetBytes;
    let suffix: NetBytes = (bytes.Slice(
      self.outgoing_start,
      self.outgoing_count - self.outgoing_start
    ).get_if<NetBytes>()) as NetBytes;
    let sent: Result<intptr, NetError> = self.connection.TryWrite(suffix);
    let failure: NetError? = sent.get_if<NetError>();
    if failure != nil {
      let error: NetError = failure as NetError;
      if error.kind != NetErrorKind.WouldBlock {
        return TlsStreamError.FromTransport(error);
      }

      let registered: TlsStreamError? = self.RegisterReadiness(true);
      if registered != nil {
        return registered as TlsStreamError;
      }

      return false;
    }

    let count: intptr = (sent.get_if<intptr>()) as intptr;
    if count <= (0ip) {
      return TlsStreamError{transport_error: NetError{kind: NetErrorKind.Closed}};
    }

    self.outgoing_start = self.outgoing_start + count;
  }

  return self.outgoing_start == self.outgoing_count && self.session.PendingCiphertext() == (0ip);
}

method(TlsStreamState) FeedInput() -> TlsStreamError? {
  if self.incoming_start < self.incoming_count {
    let bytes: NetBytes = (NetBytes.FromRaw(
      &self.incoming[0],
      self.incoming_count
    ).get_if<NetBytes>()) as NetBytes;
    let suffix: NetBytes = (bytes.Slice(
      self.incoming_start,
      self.incoming_count - self.incoming_start
    ).get_if<NetBytes>()) as NetBytes;
    let fed: Result<intptr, TlsError> = self.session.FeedCiphertext(suffix);
    let error: TlsError? = fed.get_if<TlsError>();
    if error != nil {
      return TlsStreamError{tls_error: error};
    }

    self.incoming_start = self.incoming_start + ((fed.get_if<intptr>()) as intptr);
  }

  if self.incoming_start == self.incoming_count {
    self.incoming_start = 0ip;
    self.incoming_count = 0ip;
    if self.input_eof && !self.input_ended {
      let ended: Result<Unit, TlsError> = self.session.EndInput();
      let error: TlsError? = ended.get_if<TlsError>();
      if error != nil {
        return TlsStreamError{tls_error: error};
      }

      self.input_ended = true;
    }
  }

  return nil;
}

method(TlsStreamState) StepProtocol() -> Result<TlsProgress, TlsError> {
  if self.operation == TlsStreamOperation.Handshake {
    return self.session.HandshakeStep(self.options);
  }

  if self.operation == TlsStreamOperation.Shutdown {
    return self.session.ShutdownStep(self.options);
  }

  if self.operation == TlsStreamOperation.Read {
    let buffer: NetMutableBytes = (NetMutableBytes.FromRaw(
      &mut self.plaintext[0],
      self.read_capacity as intptr
    ).get_if<NetMutableBytes>()) as NetMutableBytes;

    return self.session.ReadStep(buffer, self.options);
  }

  let remaining: intptr = self.input.Len() - self.progress;
  var size: intptr = remaining;
  if size >(16384ip) {
    size = 16384ip;
  }

  let bytes: NetBytes = self.input.Bytes();
  let chunk: NetBytes = (bytes.Slice(self.progress, size).get_if<NetBytes>()) as NetBytes;

  return self.session.WriteStep(chunk, self.options);
}

/**
 * @brief Advance up to eight bounded transport/protocol rounds and at most one native wait.
 * @param maximum_wait_ms Zero polls; -1 permits the operation's original absolute control
 *   budget.
 * @returns Zero or one completed operation, or invalid Poll arguments/reentry failure.
 * @note Idle returns immediately. Read/write readiness is chosen by TLS progress and unsent
 *   ciphertext. Pending state/resources are detached before synchronous Future continuations run.
 */
pub method(TlsStream) Poll(maximum_wait_ms: int32) -> Result<int32, TlsStreamError> {
  if maximum_wait_ms < -1 {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidArgument);
  }

  let optional: arc<TlsStreamState>? = self.cell;
  if optional == nil {
    return 0;
  }

  var state: arc<TlsStreamState> = optional as arc<TlsStreamState>;
  if state.driving {
    return TlsStreamError.FromTlsKind(TlsErrorKind.InvalidState);
  }

  if state.closed || state.operation == TlsStreamOperation.Idle {
    return 0;
  }

  state.driving = true;
  var rounds: int32 = 0;
  while rounds < 8 {
    rounds = rounds + 1;
    let control: TlsStreamError? = (state).ControlError();
    if control != nil {
      return (state).Fail(control as TlsStreamError);
    }

    let pending: AsyncFuture<Result<Unit, NetError>>? = state.wait;
    if pending != nil {
      let waiting: AsyncFuture<Result<Unit, NetError>> = pending as AsyncFuture<Result<Unit, NetError>>;
      if !waiting.is_completed {
        let polled: Result<int32, NetError> = state.driver.Poll(maximum_wait_ms);
        let poll_error: NetError? = polled.get_if<NetError>();
        // Controls precede a simultaneous native readiness/error result.
        let after_wait: TlsStreamError? = (state).ControlError();
        if after_wait != nil {
          return (state).Fail(after_wait as TlsStreamError);
        }

        if poll_error != nil {
          return (state).Fail(TlsStreamError.FromTransport(poll_error as NetError));
        }

        if !waiting.is_completed {
          state.driving = false;

          return 0;
        }
      }

      state.wait = nil;
      let completed: Result<Result<Unit, NetError>, AsyncError> = waiting.GetResult();
      if completed.IsErr() {
        return (state).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.Closed));
      }

      let ready: Result<Unit, NetError> = (
        completed.get_if<Result<Unit, NetError>>()
      ) as Result<Unit, NetError>;
      let ready_error: NetError? = ready.get_if<NetError>();
      if ready_error != nil {
        return (state).Fail(TlsStreamError.FromTransport(ready_error as NetError));
      }
    }

    let flushed: Result<bool, TlsStreamError> = (state).FlushOutput();
    // Final socket progress must not publish success or an error ahead of controls.
    let after_flush: TlsStreamError? = (state).ControlError();
    if after_flush != nil {
      return (state).Fail(after_flush as TlsStreamError);
    }

    let flush_error: TlsStreamError? = flushed.get_if<TlsStreamError>();
    if flush_error != nil {
      return (state).Fail(flush_error as TlsStreamError);
    }

    if ! ((flushed.get_if<bool>()) as bool) {
      if state.wait != nil {
        state.driving = false;

        return 0;
      }

      continue;
    }

    if state.operation_done {
      return (state).Finish(nil, state.operation == TlsStreamOperation.Shutdown);
    }

    if state.operation == TlsStreamOperation.Write && state.progress == state.input.Len() {
      state.operation_done = true;
      continue;
    }

    if state.operation == TlsStreamOperation.Read && (state.read_capacity == 0 || state.peer_closed) {
      state.operation_eof = state.read_capacity != 0 && state.peer_closed;
      state.operation_done = true;
      continue;
    }

    let feed_error: TlsStreamError? = (state).FeedInput();
    if feed_error != nil {
      return (state).Fail(feed_error as TlsStreamError);
    }

    let stepped: Result<TlsProgress, TlsError> = (state).StepProtocol();
    let protocol_error: TlsError? = stepped.get_if<TlsError>();
    if protocol_error != nil {
      return (state).Fail(TlsStreamError{tls_error: protocol_error});
    }

    let progress: TlsProgress = (stepped.get_if<TlsProgress>()) as TlsProgress;
    if progress.state == TlsStepState.PeerClosed && state.operation != TlsStreamOperation.Read {
      return (state).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.UnexpectedEof));
    }

    if progress.state == TlsStepState.Complete || progress.state == TlsStepState.PeerClosed {
      if state.operation == TlsStreamOperation.Handshake {
        state.handshaken = true;
        state.operation_done = true;
      } else if state.operation == TlsStreamOperation.Write {
        state.progress = state.progress + progress.bytes_transferred;
        state.operation_done = state.progress == state.input.Len();
      } else if state.operation == TlsStreamOperation.Read {
        state.progress = progress.bytes_transferred;
        state.operation_eof = progress.state == TlsStepState.PeerClosed;
        if state.operation_eof {
          state.peer_closed = true;
        }

        let bytes: NetBytes = (NetBytes.FromRaw(
          &state.plaintext[0],
          state.progress
        ).get_if<NetBytes>()) as NetBytes;
        let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
        let copy_error: NetError? = copied.get_if<NetError>();
        if copy_error != nil {
          return (state).Fail(TlsStreamError.FromTransport(copy_error as NetError));
        }

        state.result_buffer = (copied.get_if<NetBuffer>()) as NetBuffer;
        state.operation_done = true;
      } else {
        state.operation_done = true;
      }

      continue;
    }

    if progress.state == TlsStepState.NeedOutput || state.session.PendingCiphertext() >(0ip) {
      continue;
    }

    if state.incoming_start < state.incoming_count {
      continue;
    }

    if state.input_ended {
      return (state).Fail(TlsStreamError.FromTlsKind(TlsErrorKind.UnexpectedEof));
    }

    let input: NetMutableBytes = (NetMutableBytes.FromRaw(
      &mut state.incoming[0],
      16384ip
    ).get_if<NetMutableBytes>()) as NetMutableBytes;
    let received: Result<intptr, NetError> = state.connection.TryRead(input);
    let receive_error: NetError? = received.get_if<NetError>();
    if receive_error != nil {
      let error: NetError = receive_error as NetError;
      if error.kind != NetErrorKind.WouldBlock {
        return (state).Fail(TlsStreamError.FromTransport(error));
      }

      let registered: TlsStreamError? = (state).RegisterReadiness(false);
      if registered != nil {
        return (state).Fail(registered as TlsStreamError);
      }

      state.driving = false;

      return 0;
    }

    state.incoming_start = 0ip;
    state.incoming_count = (received.get_if<intptr>()) as intptr;
    if state.incoming_count == (0ip) {
      state.input_eof = true;
    }
  }

  state.driving = false;

  return 0;
}
