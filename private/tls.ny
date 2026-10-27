/** @brief Language ownership and public error mapping around the private TLS bridge. */
module TlsEngine;
part "../tests/engine_selftest.ny";
part "../tests/stream_selftest.ny";
part "stream.ny";
part "stream_poll.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/tls.ni";
import "interface/stream.ni";

struct TlsNativeResult { status: int32; error: int32; count: intptr; }
@extern("C") func nyra_tls_client_new(peer: *const uint8, peer_size: intptr, ca_file: *const uint8, ca_size: intptr, alpn: *const uint8, alpn_size: intptr, capacity: int32, out: *mut *mut uint8) -> int32;
@extern("C") func nyra_tls_drop(handle: *mut uint8) -> void;
@extern("C") func nyra_tls_step(handle: *mut uint8, operation: int32, input: *const uint8, output: *mut uint8, size: intptr, out: *mut TlsNativeResult) -> void;
@extern("C") func nyra_tls_end_input(handle: *mut uint8) -> int32;
@extern("C") func nyra_tls_pending_output(handle: *mut uint8) -> intptr;

pub struct TlsSession { handle: *mut uint8; }
func tls_error(code: int32) -> TlsError {
  var kind: TlsErrorKind = TlsErrorKind.Protocol;
  if code == 1 { kind = TlsErrorKind.InvalidArgument; }
  else if code == 2 { kind = TlsErrorKind.TrustUnavailable; }
  else if code == 3 { kind = TlsErrorKind.CertificateRejected; }
  else if code == 4 { kind = TlsErrorKind.PeerNameMismatch; }
  else if code == 6 { kind = TlsErrorKind.UnexpectedEof; }
  else if code == 7 { kind = TlsErrorKind.Closed; }
  else if code == 8 { kind = TlsErrorKind.InvalidState; }
  else if code == 9 { kind = TlsErrorKind.ResourceExhausted; }
  return TlsError{kind: kind};
}
func tls_progress(value: ref TlsNativeResult) -> Result<TlsProgress, TlsError> {
  if value.error != 0 { return tls_error(value.error); }
  var state: TlsStepState = TlsStepState.Complete;
  if value.status == 1 { state = TlsStepState.NeedInput; }
  else if value.status == 2 { state = TlsStepState.NeedOutput; }
  else if value.status == 3 { state = TlsStepState.PeerClosed; }
  return TlsProgress{state: state, bytes_transferred: value.count};
}
func tls_step(session: ref mut TlsSession, operation: int32, input: *const uint8, output: *mut uint8, size: intptr, options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  let checked: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  let failure: NetError? = checked.get_if<NetError>();
  if failure != nil {
    session.Close();
    let error: NetError = failure as NetError;
    if error.kind == NetErrorKind.Cancelled { return TlsError{kind: TlsErrorKind.Cancelled}; }
    return TlsError{kind: TlsErrorKind.TimedOut};
  }
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(session.handle, operation, input, output, size, &mut result);
  return tls_progress(result);
}
/** @brief Transfer the sole native owner and invalidate the source. */
pub method(TlsSession) operator move() -> TlsSession {
  let handle: *mut uint8 = self.handle;
  self.handle = 0 as *mut uint8;
  return TlsSession{handle: handle};
}
/** @brief Release the native engine during language destruction. */
pub method(TlsSession) operator drop() -> void { self.Close(); }
/** @brief Construct an engine without retaining configuration strings. */
pub static method(TlsSession) NewClient(config: ref TlsClientConfig) -> Result<TlsSession, TlsError> {
  var handle: *mut uint8 = 0 as *mut uint8;
  var capacity: int32 = config.ciphertext_capacity;
  if capacity == 0 { capacity = 32768; }
  let code: int32 = nyra_tls_client_new(config.peer_name.data as *const uint8, config.peer_name.length as intptr,
    config.ca_file.data as *const uint8, config.ca_file.length as intptr,
    config.alpn.data as *const uint8, config.alpn.length as intptr, capacity, &mut handle);
  if code != 0 { return tls_error(code); }
  return TlsSession{handle: handle};
}
/** @brief Drive one verified handshake step under the caller's controls. */
pub method(TlsSession) HandshakeStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 0, 0 as *const uint8, 0 as *mut uint8, 0 as intptr, options);
}
/** @brief Borrow caller storage for one plaintext read step. */
pub method(TlsSession) ReadStep(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 1, 0 as *const uint8, buffer.Data(), buffer.Len(), options);
}
/** @brief Copy or retry one bounded plaintext block. */
pub method(TlsSession) WriteStep(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 2, buffer.Data(), 0 as *mut uint8, buffer.Len(), options);
}
/** @brief Drive the bidirectional TLS shutdown exchange. */
pub method(TlsSession) ShutdownStep(options: ref NetOperationOptions) -> Result<TlsProgress, TlsError> {
  return tls_step(self, 3, 0 as *const uint8, 0 as *mut uint8, 0 as intptr, options);
}
/** @brief Admit ciphertext without exceeding the input queue. */
pub method(TlsSession) FeedCiphertext(buffer: ref NetBytes) -> Result<intptr, TlsError> {
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 4, buffer.Data(), 0 as *mut uint8, buffer.Len(), &mut result);
  if result.error != 0 { return tls_error(result.error); }
  return result.count;
}
/** @brief Remove outbound ciphertext without waiting. */
pub method(TlsSession) DrainCiphertext(buffer: ref NetMutableBytes) -> Result<intptr, TlsError> {
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 5, 0 as *const uint8, buffer.Data(), buffer.Len(), &mut result);
  if result.error != 0 { return tls_error(result.error); }
  return result.count;
}
/** @brief Query the currently queued output size. */
pub method(TlsSession) PendingCiphertext() -> intptr { return nyra_tls_pending_output(self.handle); }
/** @brief Mark transport FIN without treating it as close_notify. */
pub method(TlsSession) EndInput() -> Result<Unit, TlsError> {
  let code: int32 = nyra_tls_end_input(self.handle);
  if code != 0 { return tls_error(code); }
  return UnitValue();
}
/** @brief Copy the negotiated ALPN bytes into a language-owned string. */
pub method(TlsSession) SelectedAlpn() -> Result<string, TlsError> {
  var bytes: <uint8>[255] = <uint8>[255]{};
  var result: TlsNativeResult = TlsNativeResult{};
  nyra_tls_step(self.handle, 6, 0 as *const uint8, &mut bytes[0], 255 as intptr, &mut result);
  if result.error != 0 { return tls_error(result.error); }
  return string.ViewFrom(&bytes[0] as *const int8, result.count as int32).Substring(0, result.count as int32);
}
/** @brief Query owner presence only. */
pub method(TlsSession) IsOpen() -> bool { return self.handle != nil; }
/** @brief Invalidate before native cleanup so repeated Close/drop is inert. */
pub method(TlsSession) Close() -> void {
  let handle: *mut uint8 = self.handle;
  self.handle = 0 as *mut uint8;
  nyra_tls_drop(handle);
}
