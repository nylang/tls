/** @brief Optional channel ownership, provider scheduling and preserved accepted plaintext. */
part of TlsEngine;
func tls_channel_test_new(mode: int32, size: int32) -> TlsChannel {
  var connection: TcpConnection = tls_stream_test_connection(mode,size);
  var config: TlsClientConfig = tls_test_config(); config.ciphertext_capacity=0;
  var made: Result<TlsChannel,TlsStreamError> = TlsChannel.NewClient(connection,config);
  tls_test_assert(made.IsOk() && !connection.IsOpen(),"channel adopts TCP exactly once");
  return move((made.get_if<TlsChannel>()) as TlsChannel);
}
func tls_channel_test_flush(channel: ref mut TlsChannel, options: ref NetOperationOptions) -> bool {
  var count: int32=0;
  while count<50000 {
    count=count+1; let result: Result<bool,TlsStreamError> = channel.Flush(options);
    if result.IsErr() { return false; } if (result.get_if<bool>()) as bool { return true; }
    if channel.Wait(false,true,-1,options).IsErr() { return false; }
  }
  return false;
}
func tls_channel_test_write(channel: ref mut TlsChannel, block: ref NetBuffer, options: ref NetOperationOptions) -> bool {
  var count: int32=0;
  while count<50000 {
    count=count+1; let result: Result<TlsChannelWrite,TlsStreamError> = channel.WriteAvailable(block,options);
    if result.IsErr() { return false; } let write: TlsChannelWrite = (result.get_if<TlsChannelWrite>()) as TlsChannelWrite;
    if write.transfer.error!=nil { return false; }
    if write.transfer.bytes_transferred==block.Len() { return true; }
    if write.transfer.bytes_transferred!=(0 as intptr) { return false; }
    if write.state==TlsChannelWriteState.RetryRead { return false; }
    if channel.Wait(write.state==TlsChannelWriteState.NeedRead,write.state!=TlsChannelWriteState.NeedRead,-1,options).IsErr() { return false; }
  }
  return false;
}
func tls_channel_test_read(channel: ref mut TlsChannel, options: ref NetOperationOptions) -> Result<TlsTransfer,TlsStreamError> {
  var count: int32=0;
  while count<50000 {
    count=count+1; let result: Result<TlsChannelRead,TlsStreamError> = channel.ReadAvailable(options);
    if result.IsErr() { return (result.get_if<TlsStreamError>()) as TlsStreamError; }
    let read: TlsChannelRead = (result.get_if<TlsChannelRead>()) as TlsChannelRead;
    if read.state==TlsChannelReadState.Ready { return read.transfer; }
    if read.state==TlsChannelReadState.RetryWrite { return tls_stream_error(TlsErrorKind.InvalidState); }
    if read.state==TlsChannelReadState.Again { continue; }
    let waited: Result<Unit,TlsStreamError> = channel.Wait(read.state==TlsChannelReadState.NeedRead,read.state==TlsChannelReadState.NeedWrite,-1,options);
    if waited.IsErr() { return (waited.get_if<TlsStreamError>()) as TlsStreamError; }
  }
  return tls_stream_error(TlsErrorKind.InvalidState);
}
@test(tag="tls_engine")
func test_tls_channel_validation_before_adoption() {
  var empty: TlsChannel = TlsChannel{};
  tls_test_assert(!empty.IsOpen() && empty.Handshake(tls_stream_test_options()).IsErr() && empty.Flush(tls_stream_test_options()).IsErr(),"default channel remains closed");
  var connection: TcpConnection = tls_stream_test_connection(5,0);
  let config: TlsClientConfig = tls_test_config();
  tls_test_assert(TlsChannel.NewClient(connection,config).IsErr() && connection.IsOpen(),"small BIO rejection leaves socket ownership untouched");
  let ignored: Result<Unit,NetError> = connection.Close();
  tls_test_assert(nyra_tls_test_server_join()==0,"unadopted socket can be closed normally");
  empty.Close(); empty.Close();
}
func tls_channel_test_echo(mode: int32) -> void {
  var original: TlsChannel = tls_channel_test_new(mode,65536);
  var channel: TlsChannel = move(original);
  let options: NetOperationOptions = tls_stream_test_options();
  tls_test_assert(channel.Handshake(options).IsOk(),"channel performs verified handshake");
  if mode==6 {
    let updated: Result<TlsTransfer,TlsStreamError> = tls_channel_test_read(channel,options);
    tls_test_assert(updated.IsOk() && ((updated.get_if<TlsTransfer>()) as TlsTransfer).bytes_transferred==(10 as intptr),"channel handles requested peer KeyUpdate before upload");
  }
  let alpn: Result<string,TlsStreamError> = channel.SelectedAlpn();
  tls_test_assert(alpn.IsOk() && ((alpn.get_if<string>()) as string).length==0,"channel exposes absent ALPN from this controlled peer");
  nyra_tls_test_write_controls(317,5,-1);
  let block: NetBuffer = tls_stream_test_payload(16384);
  var sent: int32=0; while sent<4 { tls_test_assert(tls_channel_test_write(channel,block,options),"bounded channel write accepted once"); sent=sent+1; }
  tls_test_assert(tls_channel_test_flush(channel,options),"channel flush preserves ciphertext suffixes");
  var total: intptr=0 as intptr; var eof: bool=false; var held: NetBuffer=NetBuffer{};
  while !eof {
    let result: Result<TlsTransfer,TlsStreamError> = tls_channel_test_read(channel,options);
    tls_test_assert(result.IsOk(),"channel receives authenticated data"); if result.IsErr() { break; }
    let read: TlsTransfer = (result.get_if<TlsTransfer>()) as TlsTransfer;
    tls_test_assert(read.error==nil,"channel read carries no terminal failure"); if read.error!=nil { break; }
    var i: intptr=0 as intptr;
    unsafe { while i<read.buffer.Len() { tls_test_assert(read.buffer.Bytes().Data()[i as int32]==(((total+i)%(16384 as intptr))%(251 as intptr)) as uint8,"channel echo preserves exact plaintext order"); i=i+(1 as intptr); } }
    if held.Len()==(0 as intptr) { held=read.buffer; } total=total+read.bytes_transferred; eof=read.eof;
  }
  tls_test_assert(eof && total==(65536 as intptr),"channel distinguishes authenticated EOF from transfer completion");
  tls_test_assert(channel.Shutdown(options).IsOk() && !channel.IsOpen(),"channel flushes close_notify and retires ownership");
  tls_test_assert(held.Len()>(0 as intptr) && nyra_tls_test_partial_writes()>0 && nyra_tls_test_write_stalls()>0,"owned read bytes survive retirement and short writes/stalls were exercised");
  channel.Close(); tls_test_assert(nyra_tls_test_server_join()==0,"channel peer receives orderly closure");
}
@test(tag="tls_engine")
func test_tls_channel_short_writes_and_owned_reads() { tls_channel_test_echo(0); }
@test(tag="tls_engine")
func test_tls_channel_requested_key_update_before_upload() { tls_channel_test_echo(6); }
@test(tag="tls_engine")
func test_tls_channel_abort_does_not_flush_accepted_plaintext() {
  var channel: TlsChannel = tls_channel_test_new(3,0);
  let options: NetOperationOptions = tls_stream_test_options(); tls_test_assert(channel.Handshake(options).IsOk(),"abort fixture handshake completes");
  nyra_tls_test_write_controls(317,0,-1);
  let result: Result<TlsChannelWrite,TlsStreamError> = channel.WriteAvailable(tls_stream_test_payload(16384),options);
  tls_test_assert(result.IsOk() && ((result.get_if<TlsChannelWrite>()) as TlsChannelWrite).transfer.bytes_transferred==(16384 as intptr),"TLS acceptance is returned before TCP ciphertext flush");
  tls_test_assert(channel.Shutdown(options).IsErr() && channel.IsOpen(),"graceful shutdown cannot silently flush an unfinished upload");
  channel.Close(); channel.Close();
  tls_test_assert(!channel.IsOpen() && nyra_tls_test_written_bytes()==0,"abort retires accepted ciphertext without sending it");
  tls_test_assert(nyra_tls_test_server_join()==0,"aborted peer releases its resources");
}
@test(tag="tls_engine")
func test_tls_channel_cancel_after_acceptance_preserves_transfer() {
  var channel: TlsChannel = tls_channel_test_new(3,0);
  let token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{cancellation:token,deadline:NetDeadline.After(NetClock.NowNanoseconds(),10000000000u64)};
  tls_test_assert(channel.Handshake(options).IsOk(),"cancel fixture handshake completes"); nyra_tls_test_write_controls(317,0,-1);
  let written: Result<TlsChannelWrite,TlsStreamError> = channel.WriteAvailable(tls_stream_test_payload(16384),options); token.Cancel();
  let failed: Result<bool,TlsStreamError> = channel.Flush(options);
  tls_test_assert(written.IsOk() && ((written.get_if<TlsChannelWrite>()) as TlsChannelWrite).transfer.bytes_transferred==(16384 as intptr),"later cancellation never changes the returned accepted plaintext count");
  tls_test_assert(failed.IsErr() && ((failed.get_if<TlsStreamError>()) as TlsStreamError).tls_error!=nil && (((failed.get_if<TlsStreamError>()) as TlsStreamError).tls_error as TlsError).kind==TlsErrorKind.Cancelled && !channel.IsOpen() && nyra_tls_test_written_bytes()==0,"cancellation retires unsent ciphertext");
  tls_test_assert(nyra_tls_test_server_join()==0,"cancelled peer releases its resources");
}
@test(tag="tls_engine")
func test_tls_channel_native_failure_and_sticky_cause() {
  var channel: TlsChannel = tls_channel_test_new(3,0); let options: NetOperationOptions=tls_stream_test_options();
  tls_test_assert(channel.Handshake(options).IsOk(),"native failure fixture handshake completes"); nyra_tls_test_write_controls(317,0,0);
  let written: Result<TlsChannelWrite,TlsStreamError> = channel.WriteAvailable(tls_stream_test_payload(16384),options);
  tls_test_assert(written.IsOk() && ((written.get_if<TlsChannelWrite>()) as TlsChannelWrite).transfer.bytes_transferred==(16384 as intptr),"record accepted before transport failure");
  let failed: Result<bool,TlsStreamError> = channel.Flush(options);
  tls_test_assert(failed.IsErr() && ((failed.get_if<TlsStreamError>()) as TlsStreamError).transport_error!=nil && !channel.IsOpen(),"native flush failure retires channel");
  channel.Close(); let again: Result<TlsChannelRead,TlsStreamError> = channel.ReadAvailable(options);
  tls_test_assert(again.IsErr() && ((again.get_if<TlsStreamError>()) as TlsStreamError).transport_error!=nil,"Close preserves original transport cause");
  tls_test_assert(nyra_tls_test_server_join()==0,"failed peer releases its resources");
}
@test(tag="tls_engine")
func test_tls_channel_truncation_is_not_authenticated_eof() {
  var channel: TlsChannel = tls_channel_test_new(2,0); let options: NetOperationOptions=tls_stream_test_options();
  tls_test_assert(channel.Handshake(options).IsOk(),"truncation fixture handshake completes");
  let prefix: Result<TlsTransfer,TlsStreamError> = tls_channel_test_read(channel,options);
  tls_test_assert(prefix.IsOk() && ((prefix.get_if<TlsTransfer>()) as TlsTransfer).bytes_transferred==(6 as intptr) && !((prefix.get_if<TlsTransfer>()) as TlsTransfer).eof,"authenticated prefix survives raw FIN");
  let ended: Result<TlsTransfer,TlsStreamError> = tls_channel_test_read(channel,options);
  tls_test_assert(ended.IsErr() && ((ended.get_if<TlsStreamError>()) as TlsStreamError).tls_error!=nil && (((ended.get_if<TlsStreamError>()) as TlsStreamError).tls_error as TlsError).kind==TlsErrorKind.UnexpectedEof,"raw TLS truncation remains a TLS error");
  tls_test_assert(nyra_tls_test_server_join()==0,"truncated peer releases resources");
}
