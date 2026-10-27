#ifndef NYRA_TLS_ENGINE_PEER_H
#define NYRA_TLS_ENGINE_PEER_H
/* Controlled in-process TLS peer; certificates and cryptography stay in OpenSSL. */
#include "tls_engine.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ERR_print_errors_fp(stderr); exit(1); } } while (0)
static const char *ca_path, *cert_path, *key_path;
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
static void verify_handshake(int version, const char *name, const char *alpn) {
  ntls_session *c = client(name, ca_path, alpn, 1024); SSL *s = server(version); link wire = {0};
  int handshake_error = handshake(c, s, &wire);
  if (handshake_error) fprintf(stderr, "healthy handshake failed: %d\n", handshake_error);
  CHECK(handshake_error == NTLS_OK);
  CHECK(SSL_version(s) == version);
  uint8_t protocol[255]; ntls_result selected = nyra_tls_alpn(c, protocol, sizeof(protocol));
  CHECK(!selected.error && selected.count == (intptr_t)strlen(alpn));
  CHECK(!memcmp(protocol, alpn, (size_t)selected.count));
  if (strchr(name, ':') || !strcmp(name, "127.0.0.1")) CHECK(!SSL_get_servername(s, TLSEXT_NAMETYPE_host_name));
  else CHECK(!strcmp(SSL_get_servername(s, TLSEXT_NAMETYPE_host_name), name));
  nyra_tls_drop(c); SSL_free(s);
}
#endif
