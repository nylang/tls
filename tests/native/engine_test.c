/* Controlled in-process TLS peer; certificates and cryptography stay in OpenSSL. */
#include "tls_engine.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ERR_print_errors_fp(stderr); exit(1); } } while (0)
static const char *ca_path, *cert_path, *key_path, *other_ca;
static int passed;
static ntls_session *client(const char *name, const char *ca, const char *alpn, int capacity) {
  ntls_session *s = NULL;
  CHECK(nyra_tls_client_new((const uint8_t *)name, (intptr_t)strlen(name),
      (const uint8_t *)ca, (intptr_t)strlen(ca), (const uint8_t *)alpn,
      (intptr_t)strlen(alpn), capacity, &s) == NTLS_OK);
  CHECK(s); return s;
}
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_size,
    const unsigned char *in, unsigned int in_size, void *arg) {
  (void)ssl; (void)arg;
  static const unsigned char choices[] = {8,'h','t','t','p','/','1','.','1'};
  return SSL_select_next_proto((unsigned char **)out, out_size, choices, sizeof(choices), in, in_size)
      == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
}
static SSL *server(int version) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); CHECK(ctx);
  CHECK(SSL_CTX_set_min_proto_version(ctx, version));
  CHECK(SSL_CTX_set_max_proto_version(ctx, version));
  CHECK(SSL_CTX_use_certificate_chain_file(ctx, cert_path));
  CHECK(SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM));
  CHECK(SSL_CTX_check_private_key(ctx));
  SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
  SSL *s = SSL_new(ctx); CHECK(s); SSL_CTX_free(ctx);
  BIO *input = BIO_new(BIO_s_mem()), *output = BIO_new(BIO_s_mem()); CHECK(input && output);
  BIO_set_mem_eof_return(input, -1); BIO_set_mem_eof_return(output, -1);
  SSL_set_bio(s, input, output); SSL_set_accept_state(s); return s;
}
typedef struct link { uint8_t buffer[65536]; size_t start, size; } link;
static void relay(ntls_session *c, SSL *s, link *wire) {
  uint8_t scratch[127];
  ntls_result drained = nyra_tls_drain(c, scratch, sizeof(scratch)); CHECK(!drained.error);
  if (drained.count) CHECK(BIO_write(SSL_get_rbio(s), scratch, (int)drained.count) == drained.count);
  if (wire->start == wire->size) {
    int count = BIO_read(SSL_get_wbio(s), wire->buffer, sizeof(wire->buffer));
    wire->start = 0; wire->size = count > 0 ? (size_t)count : 0;
  }
  if (wire->size > wire->start) {
    size_t size = wire->size - wire->start; if (size > 113) size = 113;
    ntls_result fed = nyra_tls_feed(c, wire->buffer + wire->start, (intptr_t)size); CHECK(!fed.error);
    CHECK(fed.count >= 0 && (size_t)fed.count <= size); wire->start += (size_t)fed.count;
  }
}
static int handshake(ntls_session *c, SSL *s, link *wire) {
  int client_done = 0, server_done = 0;
  for (int i = 0; i < 20000; ++i) {
    if (!client_done) {
      ntls_result r = nyra_tls_handshake(c);
      if (r.error) return r.error;
      client_done = r.status == NTLS_COMPLETE;
    }
    if (!server_done) {
      ERR_clear_error(); int rc = SSL_do_handshake(s);
      int error = SSL_get_error(s, rc);
      if (rc == 1) server_done = 1;
      else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return NTLS_PROTOCOL;
    }
    relay(c, s, wire);
    if (client_done && server_done && !nyra_tls_pending_output(c) &&
        wire->size == wire->start && !BIO_ctrl_pending(SSL_get_wbio(s))) return NTLS_OK;
  }
  CHECK(0); return NTLS_PROTOCOL;
}
static void pass(const char *name) { ++passed; printf("PASS %s\n", name); }
static void verify_handshake(int version, const char *name, const char *alpn) {
  ntls_session *c = client(name, ca_path, alpn, 1024); SSL *s = server(version); link wire = {0};
  CHECK(handshake(c, s, &wire) == NTLS_OK);
  CHECK(SSL_version(s) == version);
  uint8_t protocol[255]; ntls_result selected = nyra_tls_alpn(c, protocol, sizeof(protocol));
  CHECK(!selected.error && selected.count == (intptr_t)strlen(alpn));
  CHECK(!memcmp(protocol, alpn, (size_t)selected.count));
  if (strchr(name, ':') || !strcmp(name, "127.0.0.1")) CHECK(!SSL_get_servername(s, TLSEXT_NAMETYPE_host_name));
  else CHECK(!strcmp(SSL_get_servername(s, TLSEXT_NAMETYPE_host_name), name));
  nyra_tls_drop(c); SSL_free(s);
}
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
static void rejected_peer(const char *name, const char *ca, int expected) {
  ntls_session *c = client(name, ca, "http/1.1", 1024); SSL *s = server(TLS1_3_VERSION); link wire = {0};
  CHECK(handshake(c, s, &wire) == expected);
  CHECK(nyra_tls_handshake(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_shutdown(c).error == NTLS_CLOSED);
  nyra_tls_drop(c); SSL_free(s);
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
  CHECK(argc == 7); ca_path = argv[1]; cert_path = argv[2]; key_path = argv[3]; other_ca = argv[4];
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
