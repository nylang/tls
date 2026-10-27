#include "engine_peer.h"
static const char *other_ca;
static int passed;
static void pass(const char *name) { ++passed; printf("PASS %s\n", name); }
static void write_and_read(void) {
  ntls_session *c = client("localhost", ca_path, "http/1.1", 1024); SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t payload[16384], output[16384];
  for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i % 251);
  int finished = 0, saw_backpressure = 0; size_t total = 0;
  for (int i = 0; i < 20000 && (total < sizeof(payload) || !finished); ++i) {
    if (!finished) {
      ntls_result r = nyra_tls_write(c, payload, sizeof(payload)); CHECK(!r.error);
      if (r.status == NTLS_COMPLETE) { CHECK(r.count == sizeof(payload)); finished = 1; }
      else {
        saw_backpressure = 1;
        uint8_t wrong = 9; CHECK(nyra_tls_write(c, &wrong, 1).error == NTLS_STATE);
        CHECK(nyra_tls_read(c, output, 1).error == NTLS_STATE);
      }
    }
    relay(c, s, &wire);
    if (total < sizeof(payload)) {
      size_t count = 0; ERR_clear_error();
      int rc = SSL_read_ex(s, output + total, sizeof(output) - total, &count);
      int error = SSL_get_error(s, rc);
      CHECK(rc == 1 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
      total += count;
    }
  }
  CHECK(finished && saw_backpressure && total == sizeof(payload) && !memcmp(output, payload, total));
  pass("bounded output, stable write retries and patterned 16 KiB transfer");
  size_t count = 0; CHECK(SSL_write_ex(s, "reply", 5, &count) && count == 5);
  int read_done = 0;
  for (int i = 0; i < 20000 && !read_done; ++i) {
    relay(c, s, &wire);
    ntls_result r = nyra_tls_read(c, output, sizeof(output)); CHECK(!r.error);
    if (r.status == NTLS_COMPLETE) { CHECK(r.count == 5 && !memcmp(output, "reply", 5)); read_done = 1; }
  }
  CHECK(read_done); pass("fragmented TLS application read");
  int client_done = 0, server_done = 0;
  for (int i = 0; i < 20000 && (!client_done || !server_done || nyra_tls_pending_output(c)); ++i) {
    if (!client_done) { ntls_result r = nyra_tls_shutdown(c); CHECK(!r.error); client_done = r.status == NTLS_COMPLETE; }
    if (!server_done) {
      ERR_clear_error(); int rc = SSL_shutdown(s); int error = rc < 0 ? SSL_get_error(s, rc) : SSL_ERROR_NONE;
      CHECK(rc >= 0 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE); server_done = rc == 1;
    }
    relay(c, s, &wire);
  }
  CHECK(client_done && server_done); CHECK(nyra_tls_write(c, payload, 1).error == NTLS_STATE);
  pass("bidirectional authenticated shutdown");
  nyra_tls_drop(c); SSL_free(s);
}
static void check_terminal(ntls_session *c) {
  uint8_t out[64];
  CHECK(nyra_tls_handshake(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_read(c, out, sizeof(out)).error == NTLS_CLOSED);
  CHECK(nyra_tls_write(c, out, 1).error == NTLS_CLOSED);
  CHECK(nyra_tls_shutdown(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_feed(c, out, 1).error == NTLS_CLOSED);
  CHECK(nyra_tls_end_input(c) == NTLS_CLOSED);
  CHECK(nyra_tls_alpn(c, out, sizeof(out)).error == NTLS_CLOSED);
}
static void bad_record(int version, int replay) {
  ntls_session *c = client("localhost", ca_path, "", 1024);
  SSL *s = server(version); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t out[64], ciphertext[512]; memset(out, 0xa5, sizeof(out));
  /* Consume ordinary post-handshake tickets and establish a pending read. */
  ntls_result pending = nyra_tls_read(c, out, sizeof(out));
  CHECK(!pending.error && pending.status == NTLS_INPUT && !pending.count);
  size_t written = 0;
  CHECK(SSL_write_ex(s, "authenticated", 13, &written) && written == 13);
  int size = BIO_read(SSL_get_wbio(s), ciphertext, sizeof(ciphertext));
  CHECK(size > 5 && ciphertext[0] == SSL3_RT_APPLICATION_DATA);
  CHECK(size == 5 + ((int)ciphertext[3] << 8) + ciphertext[4]);
  if (replay) {
    ntls_result fed = nyra_tls_feed(c, ciphertext, size); CHECK(!fed.error && fed.count == size);
    ntls_result first = nyra_tls_read(c, out, sizeof(out));
    CHECK(!first.error && first.status == NTLS_COMPLETE && first.count == 13);
    CHECK(!memcmp(out, "authenticated", 13));
  } else {
    /* Alter the authentication tag, preserving the complete record framing. */
    ciphertext[size - 1] ^= 1;
  }
  memset(out, 0xa5, sizeof(out));
  int failure = 0;
  for (int offset = 0; offset < size;) {
    int amount = size - offset; if (amount > 7) amount = 7;
    ntls_result fed = nyra_tls_feed(c, ciphertext + offset, amount);
    CHECK(!fed.error && fed.count == amount); offset += amount;
    ntls_result read = nyra_tls_read(c, out, sizeof(out));
    CHECK(!read.count && read.status != NTLS_PEER_CLOSED);
    for (size_t i = 0; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
    if (read.error) { CHECK(read.error == NTLS_PROTOCOL && offset == size); failure = 1; }
    else CHECK(read.status == NTLS_INPUT);
  }
  CHECK(failure); check_terminal(c);
  /* Fatal-alert output may be drained, but the engine cannot resume plaintext. */
  ntls_result alert = nyra_tls_drain(c, out, sizeof(out)); CHECK(!alert.error);
  nyra_tls_drop(c); SSL_free(s);
  verify_handshake(version, "localhost", "");
}
static void client_message(ntls_session *c, SSL *s, link *wire, const uint8_t *data, size_t size) {
  ntls_result sent = nyra_tls_write(c, data, (intptr_t)size);
  CHECK(!sent.error && sent.status == NTLS_COMPLETE && sent.count == (intptr_t)size);
  uint8_t received[64]; size_t total = 0;
  CHECK(size <= sizeof(received));
  for (int i = 0; i < 20000 && total < size; ++i) {
    relay(c, s, wire);
    size_t count = 0; ERR_clear_error();
    int rc = SSL_read_ex(s, received + total, sizeof(received) - total, &count);
    int error = SSL_get_error(s, rc);
    CHECK(rc == 1 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
    total += count;
  }
  CHECK(total == size && !memcmp(received, data, size));
}
static void key_update_message(int writing, int version, int type, const void *buffer,
    size_t size, SSL *ssl, void *argument) {
  (void)version; (void)ssl;
  if (!writing && type == SSL3_RT_HANDSHAKE && size &&
      ((const uint8_t *)buffer)[0] == SSL3_MT_KEY_UPDATE) {
    CHECK(size == 5 && ((const uint8_t *)buffer)[4] == SSL_KEY_UPDATE_NOT_REQUESTED);
    ++*(int *)argument;
  }
}
static void key_updates(int requested) {
  ntls_session *c = client("localhost", ca_path, "", 1024);
  SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  int responses = 0;
  SSL_set_msg_callback(s, key_update_message); SSL_set_msg_callback_arg(s, &responses);
  for (int cycle = 0; cycle < 4; ++cycle) {
    uint8_t out[64], payload[32];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(cycle * 32 + i);
    ntls_result waiting = nyra_tls_read(c, out, sizeof(out));
    CHECK(!waiting.error && waiting.status == NTLS_INPUT && !waiting.count);
    CHECK(SSL_key_update(s, requested ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED));
    CHECK(SSL_do_handshake(s) == 1);
    size_t sent = 0; CHECK(SSL_write_ex(s, payload, sizeof(payload), &sent) && sent == sizeof(payload));
    int completed = 0;
    for (int i = 0; i < 20000 && !completed; ++i) {
      relay(c, s, &wire);
      ntls_result read = nyra_tls_read(c, out, sizeof(out)); CHECK(!read.error);
      if (read.status == NTLS_COMPLETE) {
        CHECK(read.count == sizeof(payload) && !memcmp(out, payload, sizeof(payload))); completed = 1;
      } else CHECK(read.status == NTLS_INPUT || read.status == NTLS_OUTPUT);
    }
    CHECK(completed);
    client_message(c, s, &wire, payload, sizeof(payload));
    CHECK(responses == (requested ? cycle + 1 : 0));
  }
  nyra_tls_drop(c); SSL_free(s);
}
static void read_retry_storage(void) {
  ntls_session *c = client("localhost", ca_path, "", 1024);
  SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t original[16], replacement[16]; memset(original, 0xa5, sizeof(original));
  ntls_result waiting = nyra_tls_read(c, original, sizeof(original));
  CHECK(!waiting.error && waiting.status == NTLS_INPUT);
  CHECK(nyra_tls_read(c, replacement, 8).error == NTLS_STATE);
  CHECK(nyra_tls_write(c, (const uint8_t *)"ack", 3).error == NTLS_STATE);
  size_t sent = 0; CHECK(SSL_write_ex(s, "preserved", 9, &sent) && sent == 9);
  int completed = 0;
  for (int i = 0; i < 20000 && !completed; ++i) {
    relay(c, s, &wire);
    ntls_result read = nyra_tls_read(c, replacement, sizeof(replacement)); CHECK(!read.error);
    if (read.status == NTLS_COMPLETE) {
      CHECK(read.count == 9 && !memcmp(replacement, "preserved", 9)); completed = 1;
    }
  }
  CHECK(completed);
  for (size_t i = 0; i < sizeof(original); ++i) CHECK(original[i] == 0xa5);
  client_message(c, s, &wire, (const uint8_t *)"ack", 3);
  nyra_tls_drop(c); SSL_free(s);
}
static void rejected_peer(const char *name, const char *ca, int expected) {
  ntls_session *c = client(name, ca, "http/1.1", 1024); SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == expected);
  CHECK(nyra_tls_handshake(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_shutdown(c).error == NTLS_CLOSED);
  nyra_tls_drop(c); SSL_free(s);
}
static void certificate_case(const char *directory, const char *file, int expected,
    int minimum_size, int maximum_size) {
  char path[4096]; int length = snprintf(path, sizeof(path), "%s/%s", directory, file);
  CHECK(length > 0 && (size_t)length < sizeof(path));
  const char *saved = cert_path; cert_path = path;
  ntls_session *c = client("localhost", ca_path, "", 1024);
  SSL *s = server(TLS1_3_VERSION); link wire = {0};
  int encoded_size = i2d_X509(SSL_get_certificate(s), NULL);
  CHECK(encoded_size >= minimum_size && encoded_size <= maximum_size);
  CHECK(handshake(c, s, &wire) == expected);
  if (expected != NTLS_OK) check_terminal(c);
  nyra_tls_drop(c); SSL_free(s); cert_path = saved;
}
static void certificate_cases(const char *directory) {
  certificate_case(directory, "chain.pem", NTLS_OK, 1, 262144);
  pass("complete intermediate chain is accepted with only its root trusted");
  certificate_case(directory, "chain-leaf.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("missing intermediate fails closed without issuer retrieval");
  certificate_case(directory, "wrong-chain.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("an intermediate with the wrong signing key is rejected");
  certificate_case(directory, "not-ca-chain.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("CA:FALSE intermediate cannot authorize a leaf");
  certificate_case(directory, "pathlen-chain.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("intermediate pathLenConstraint is enforced");
  certificate_case(directory, "wrong-eku.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("clientAuth-only leaf cannot authenticate a TLS server");
  certificate_case(directory, "future.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("not-yet-valid leaf is rejected");
  certificate_case(directory, "depth-chain-8.pem", NTLS_OK, 1, 262144);
  pass("eight intermediate certificates meet the configured verification depth");
  certificate_case(directory, "depth-chain-9.pem", NTLS_CERTIFICATE, 1, 262144);
  pass("nine intermediate certificates exceed the configured verification depth");
  certificate_case(directory, "near-limit.pem", NTLS_OK, 256000, 262000);
  pass("valid certificate below the 256 KiB message limit is accepted");
  certificate_case(directory, "over-limit.pem", NTLS_PROTOCOL, 262145, 300000);
  pass("certificate above the 256 KiB message limit fails terminally");
  verify_handshake(TLS1_3_VERSION, "localhost", "");
}
static void eof_cases(int clean) {
  ntls_session *c = client("localhost", ca_path, "", 1024); SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  if (clean) {
    CHECK(SSL_shutdown(s) == 0);
    for (int i = 0; i < 1000 && (BIO_ctrl_pending(SSL_get_wbio(s)) || wire.size != wire.start); ++i) relay(c, s, &wire);
  }
  CHECK(nyra_tls_end_input(c) == NTLS_OK); CHECK(nyra_tls_end_input(c) == NTLS_OK);
  uint8_t out[16384]; ntls_result r = nyra_tls_read(c, out, sizeof(out));
  if (clean) CHECK(!r.error && r.status == NTLS_PEER_CLOSED);
  else CHECK(r.error == NTLS_EOF);
  CHECK(nyra_tls_feed(c, out, 1).error == (clean ? NTLS_STATE : NTLS_CLOSED));
  nyra_tls_drop(c); SSL_free(s);
}
int main(int argc, char **argv) {
  CHECK(argc == 8); ca_path = argv[1]; cert_path = argv[2]; key_path = argv[3]; other_ca = argv[4];
  verify_handshake(TLS1_2_VERSION, "localhost", "http/1.1"); pass("verified TLS 1.2 DNS identity and SNI/ALPN");
  verify_handshake(TLS1_3_VERSION, "localhost", "http/1.1"); pass("verified TLS 1.3 DNS identity and SNI/ALPN");
  verify_handshake(TLS1_3_VERSION, "127.0.0.1", ""); pass("IP SAN verification without SNI and optional ALPN");
  rejected_peer("wrong.example", ca_path, NTLS_NAME); pass("hostname mismatch is terminal");
  rejected_peer("127.0.0.2", ca_path, NTLS_NAME); pass("IP SAN mismatch is terminal");
  rejected_peer("localhost", other_ca, NTLS_CERTIFICATE); pass("untrusted certificate is terminal");
  const char *valid_cert = cert_path;
  cert_path = argv[5]; rejected_peer("localhost", ca_path, NTLS_CERTIFICATE); cert_path = valid_cert;
  pass("expired certificate is rejected");
  cert_path = argv[6]; rejected_peer("localhost", ca_path, NTLS_NAME); cert_path = valid_cert;
  pass("CN-only certificate cannot replace a DNS SAN");
  ntls_session *mismatch = client("localhost", ca_path, "h2", 1024);
  SSL *peer = server(TLS1_3_VERSION); link mismatch_wire = {0};
  CHECK(handshake(mismatch, peer, &mismatch_wire) == NTLS_PROTOCOL);
  nyra_tls_drop(mismatch); SSL_free(peer); pass("ALPN mismatch fails the handshake");
  ntls_session *old = client("localhost", ca_path, "", 1024);
  peer = server(TLS1_1_VERSION); SSL_set_security_level(peer, 0); link old_wire = {0};
  CHECK(handshake(old, peer, &old_wire) == NTLS_PROTOCOL);
  nyra_tls_drop(old); SSL_free(peer); pass("TLS 1.1 is refused");
  write_and_read();
  bad_record(TLS1_2_VERSION, 0); pass("TLS 1.2 tampered record yields no plaintext and terminal Protocol error");
  bad_record(TLS1_3_VERSION, 0); pass("TLS 1.3 tampered record yields no plaintext and terminal Protocol error");
  bad_record(TLS1_2_VERSION, 1); pass("TLS 1.2 record replay never duplicates authenticated plaintext");
  bad_record(TLS1_3_VERSION, 1); pass("TLS 1.3 record replay never duplicates authenticated plaintext");
  key_updates(0); pass("four TLS 1.3 peer key updates preserve bidirectional traffic without unsolicited replies");
  key_updates(1); pass("four requested TLS 1.3 key updates rotate both directions with non-requesting replies");
  read_retry_storage(); pass("pending read rejects size changes and safely replaces caller storage");
  certificate_cases(argv[7]);
  eof_cases(0); pass("transport truncation is unexpected EOF");
  eof_cases(1); pass("close_notify remains authenticated EOF after transport FIN");
  ntls_session *c = NULL;
  CHECK(nyra_tls_client_new((const uint8_t *)"localhost", 9, (const uint8_t *)"/missing/nyra-tls-ca", 20, NULL, 0, 1024, &c) == NTLS_TRUST);
  CHECK(!c); pass("missing explicit trust fails closed");
  CHECK(nyra_tls_client_new((const uint8_t *)"local\0host", 10, (const uint8_t *)ca_path, (intptr_t)strlen(ca_path), NULL, 0, 1024, &c) == NTLS_ARGUMENT);
  CHECK(!c); pass("embedded NUL peer identity rejected");
  c = client("localhost", ca_path, "", 1024);
  uint8_t bytes[2048] = {0};
  ntls_result fed = nyra_tls_feed(c, bytes, sizeof(bytes)); CHECK(!fed.error && fed.count == 1024);
  fed = nyra_tls_feed(c, bytes, 1); CHECK(!fed.error && fed.count == 0);
  CHECK(nyra_tls_read(c, bytes, 1).error == NTLS_STATE);
  CHECK(nyra_tls_feed(c, NULL, 1).error == NTLS_ARGUMENT);
  nyra_tls_drop(c); nyra_tls_drop(NULL); pass("bounded input, invalid ranges and pre-handshake state");
  for (int i = 0; i < 64; ++i) { c = client("localhost", ca_path, "", 1024); nyra_tls_drop(c); }
  pass("64 construction/drop cycles");
  printf("%d native behavior cases passed\n", passed); return 0;
}
