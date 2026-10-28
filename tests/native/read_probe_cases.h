/* New opt-in reads must not weaken ordinary read/write retry reservations. */
static void probe_receive(ntls_session *c, SSL *s, link *wire, const char *text) {
  uint8_t out[16384]; int done = 0;
  for (int i = 0; i < 20000 && !done; ++i) {
    relay(c, s, wire);
    ntls_result r; nyra_tls_step(c, 7, NULL, out, sizeof(out), &r); CHECK(!r.error);
    if (r.status == NTLS_COMPLETE) {
      CHECK(r.count == (intptr_t)strlen(text) && !memcmp(out, text, (size_t)r.count)); done = 1;
    }
  }
  CHECK(done);
}
static void probe_peer_receive(ntls_session *c, SSL *s, link *wire, const char *text) {
  uint8_t out[64]; int done = 0;
  for (int i = 0; i < 20000 && !done; ++i) {
    relay(c, s, wire);
    size_t count = 0; ERR_clear_error(); int rc = SSL_read_ex(s, out, sizeof(out), &count);
    int error = SSL_get_error(s, rc);
    CHECK(rc == 1 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
    if (rc == 1) { CHECK(count == strlen(text) && !memcmp(out, text, count)); done = 1; }
  }
  CHECK(done);
}
static void probe_interleave(int version, int partial) {
  ntls_session *c = client("localhost", ca_path, "", 32768);
  SSL *s = server(version); link wire = {0}; CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t out[16384], cipher[512]; memset(out, 0xa5, sizeof(out));
  int size = 0;
  if (partial) {
    size_t sent = 0; CHECK(SSL_write_ex(s, "early", 5, &sent) && sent == 5);
    size = BIO_read(SSL_get_wbio(s), cipher, sizeof(cipher)); CHECK(size > 6);
    ntls_result fed = nyra_tls_feed(c, cipher, size - 1); CHECK(!fed.error && fed.count == size - 1);
  }
  ntls_result probe = nyra_tls_probe_read(c, out, sizeof(out));
  CHECK(!probe.error && probe.status == NTLS_INPUT && !probe.count);
  for (size_t i = 0; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
  ntls_result written = nyra_tls_write(c, (const uint8_t *)"req", 3);
  CHECK(!written.error && written.status == NTLS_COMPLETE && written.count == 3);
  intptr_t queued = nyra_tls_pending_output(c); CHECK(queued > 0);
  if (partial) {
    ntls_result fed = nyra_tls_feed(c, cipher + size - 1, 1); CHECK(!fed.error && fed.count == 1);
    probe = nyra_tls_probe_read(c, out, sizeof(out));
    CHECK(!probe.error && probe.status == NTLS_COMPLETE && probe.count == 5 && !memcmp(out, "early", 5));
  } else {
    probe = nyra_tls_probe_read(c, out, sizeof(out));
    CHECK(!probe.error && probe.status == NTLS_INPUT && !probe.count);
    for (size_t i = 0; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
  }
  CHECK(nyra_tls_pending_output(c) == queued);
  probe_peer_receive(c, s, &wire, "req");
  if (!partial) {
    size_t sent = 0; CHECK(SSL_write_ex(s, "reply", 5, &sent) && sent == 5);
    probe_receive(c, s, &wire, "reply");
  }
  nyra_tls_drop(c); SSL_free(s);
}
static void probe_reservations(void) {
  uint8_t out[16384], wrong[16383];
  CHECK(nyra_tls_probe_read(NULL, out, sizeof(out)).error == NTLS_CLOSED);
  ntls_session *c = client("localhost", ca_path, "", 1024);
  CHECK(nyra_tls_probe_read(c, out, sizeof(out)).error == NTLS_STATE);
  SSL *s = server(TLS1_3_VERSION); link wire = {0}; CHECK(handshake(c, s, &wire) == NTLS_OK);
  CHECK(nyra_tls_probe_read(c, wrong, sizeof(wrong)).error == NTLS_ARGUMENT);
  CHECK(nyra_tls_probe_read(c, NULL, sizeof(out)).error == NTLS_ARGUMENT);
  ntls_result read = nyra_tls_read(c, out, sizeof(out)); CHECK(!read.error && read.status == NTLS_INPUT);
  CHECK(nyra_tls_probe_read(c, out, sizeof(out)).error == NTLS_STATE);
  CHECK(nyra_tls_write(c, (const uint8_t *)"x", 1).error == NTLS_STATE);
  size_t sent = 0; CHECK(SSL_write_ex(s, "ack", 3, &sent) && sent == 3);
  int done = 0;
  for (int i = 0; i < 20000 && !done; ++i) {
    relay(c, s, &wire); read = nyra_tls_read(c, out, sizeof(out)); CHECK(!read.error);
    if (read.status == NTLS_COMPLETE) { CHECK(read.count == 3 && !memcmp(out, "ack", 3)); done = 1; }
  }
  CHECK(done);
  memset(out, 97, sizeof(out));
  ntls_result write = nyra_tls_write(c, out, sizeof(out));
  CHECK(!write.error && write.status == NTLS_OUTPUT && !write.count);
  CHECK(nyra_tls_probe_read(c, out, sizeof(out)).error == NTLS_STATE);
  nyra_tls_drop(c); SSL_free(s);
}
static void probe_terminal(int version, int mode) {
  ntls_session *c = client("localhost", ca_path, "", 32768);
  SSL *s = server(version); link wire = {0}; CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t out[16384], cipher[512]; memset(out, 0xa5, sizeof(out));
  if (mode == 0) CHECK(nyra_tls_end_input(c) == NTLS_OK);
  else {
    size_t sent = 0;
    if (mode == 1) CHECK(SSL_write_ex(s, "secret", 6, &sent) && sent == 6);
    else CHECK(SSL_shutdown(s) == 0);
    int size = BIO_read(SSL_get_wbio(s), cipher, sizeof(cipher)); CHECK(size > 5);
    if (mode == 1) cipher[size - 1] ^= 0x80;
    ntls_result fed = nyra_tls_feed(c, cipher, size); CHECK(!fed.error && fed.count == size);
    if (mode == 2) CHECK(nyra_tls_end_input(c) == NTLS_OK);
  }
  ntls_result probe = nyra_tls_probe_read(c, out, sizeof(out)); CHECK(!probe.count);
  if (mode == 0) CHECK(probe.error == NTLS_EOF);
  else if (mode == 1) CHECK(probe.error == NTLS_PROTOCOL);
  else CHECK(!probe.error && probe.status == NTLS_PEER_CLOSED);
  for (size_t i = 0; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
  probe = nyra_tls_probe_read(c, out, sizeof(out));
  if (mode == 2) CHECK(!probe.error && probe.status == NTLS_PEER_CLOSED && !probe.count);
  else CHECK(probe.error == NTLS_CLOSED);
  nyra_tls_drop(c); SSL_free(s);
}
static void read_probe_cases(void) {
  probe_interleave(TLS1_2_VERSION, 0); pass("TLS 1.2 idle read probe permits a write without flushing queued ciphertext");
  probe_interleave(TLS1_3_VERSION, 0); pass("TLS 1.3 idle read probe permits a write without flushing queued ciphertext");
  probe_interleave(TLS1_2_VERSION, 1); pass("TLS 1.2 partial record probe interleaves writes and authenticates early plaintext before flushing upload");
  probe_interleave(TLS1_3_VERSION, 1); pass("TLS 1.3 partial record probe interleaves writes and authenticates early plaintext before flushing upload");
  probe_reservations(); pass("probe validation preserves ordinary pending read/write reservations");
  probe_terminal(TLS1_2_VERSION, 0); pass("TLS 1.2 probe reports truncation without plaintext or authenticated EOF");
  probe_terminal(TLS1_3_VERSION, 0); pass("TLS 1.3 probe reports truncation without plaintext or authenticated EOF");
  probe_terminal(TLS1_2_VERSION, 1); pass("TLS 1.2 probe never exposes tampered plaintext");
  probe_terminal(TLS1_3_VERSION, 1); pass("TLS 1.3 probe never exposes tampered plaintext");
  probe_terminal(TLS1_2_VERSION, 2); pass("TLS 1.2 probe authenticates close_notify before transport FIN");
  probe_terminal(TLS1_3_VERSION, 2); pass("TLS 1.3 probe authenticates close_notify before transport FIN");
}
