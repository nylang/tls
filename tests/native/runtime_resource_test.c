// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/* Each invocation owns a fresh provider and fails one real allocation in one step. */
#include "engine_peer.h"

typedef union allocation {
  max_align_t alignment;
  struct { size_t size; } value;
} allocation;
static size_t live, attempts, fail_at, hits;
static int injecting;
static int refuse(void) {
  if (!injecting) return 0;
  ++attempts;
  if (!fail_at || attempts != fail_at) return 0;
  ++hits; return 1;
}
static void *provider_malloc(size_t size, const char *file, int line) {
  (void)file; (void)line;
  if (refuse() || size > SIZE_MAX - sizeof(allocation)) return NULL;
  allocation *value = malloc(sizeof(*value) + size);
  if (!value) return NULL;
  value->value.size = size; ++live; return value + 1;
}
static void provider_free(void *pointer, const char *file, int line) {
  (void)file; (void)line;
  if (!pointer) return;
  CHECK(live); --live; free((allocation *)pointer - 1);
}
static void *provider_realloc(void *pointer, size_t size, const char *file, int line) {
  if (!pointer) return provider_malloc(size, file, line);
  if (!size) { provider_free(pointer, file, line); return NULL; }
  if (refuse() || size > SIZE_MAX - sizeof(allocation)) return NULL;
  allocation *value = realloc((allocation *)pointer - 1, sizeof(*value) + size);
  if (!value) return NULL;
  value->value.size = size; return value + 1;
}
static void terminal(ntls_session *c) {
  uint8_t out[16];
  CHECK(nyra_tls_handshake(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_read(c, out, sizeof(out)).error == NTLS_CLOSED);
  CHECK(nyra_tls_write(c, out, 1).error == NTLS_CLOSED);
  CHECK(nyra_tls_shutdown(c).error == NTLS_CLOSED);
  CHECK(nyra_tls_feed(c, out, 1).error == NTLS_CLOSED);
  CHECK(nyra_tls_end_input(c) == NTLS_CLOSED);
  CHECK(nyra_tls_alpn(c, out, sizeof(out)).error == NTLS_CLOSED);
  /* Draining any queued flight remains permitted after terminal failure. */
  CHECK(!nyra_tls_drain(c, out, sizeof(out)).error);
}
static void finish_shutdown(ntls_session *c, SSL *s, link *wire) {
  int client_done = 0, server_done = 0;
  for (int i = 0; i < 20000 && (!client_done || !server_done); ++i) {
    if (!client_done) {
      ntls_result r = nyra_tls_shutdown(c); CHECK(!r.error);
      client_done = r.status == NTLS_COMPLETE;
    }
    if (!server_done) {
      ERR_clear_error(); int rc = SSL_shutdown(s);
      int error = rc < 0 ? SSL_get_error(s, rc) : SSL_ERROR_NONE;
      CHECK(rc >= 0 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
      server_done = rc == 1;
    }
    relay(c, s, wire);
  }
  CHECK(client_done && server_done);
}
static ntls_result later_handshake(ntls_session *c, SSL *s, link *wire) {
  /* The initial ClientHello is outside this window. Inject only client steps;
   * peer cryptography, relay storage and peer alerts never consume an index. */
  ntls_result initial = nyra_tls_handshake(c);
  CHECK(!initial.error && initial.status == NTLS_OUTPUT);
  while (nyra_tls_pending_output(c)) relay(c, s, wire);
  int client_done = 0, server_done = 0, peer_failed = 0;
  ntls_result result = {NTLS_INPUT, NTLS_OK, 0};
  for (int i = 0; i < 20000; ++i) {
    if (!server_done && !peer_failed) {
      ERR_clear_error(); int rc = SSL_do_handshake(s);
      int error = SSL_get_error(s, rc);
      if (rc == 1) server_done = 1;
      else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) peer_failed = 1;
    }
    relay(c, s, wire);
    if (!client_done) {
      injecting = 1; result = nyra_tls_handshake(c); injecting = 0;
      if (result.error) return result;
      client_done = result.status == NTLS_COMPLETE;
    }
    if (client_done && server_done && !nyra_tls_pending_output(c) &&
        wire->size == wire->start && !BIO_ctrl_pending(SSL_get_wbio(s))) return result;
  }
  CHECK(0); return result;
}
int main(int argc, char **argv) {
  CHECK(argc == 7);
  /* Install before any OpenSSL initialization, independently in every process. */
  CHECK(CRYPTO_set_mem_functions(provider_malloc, provider_realloc, provider_free));
  ca_path = argv[1]; cert_path = argv[2]; key_path = argv[3];
  int version = atoi(argv[4]) == 12 ? TLS1_2_VERSION : TLS1_3_VERSION;
  int operation = atoi(argv[5]); CHECK(operation >= 0 && operation <= 5);
  fail_at = (size_t)strtoul(argv[6], NULL, 10);
  ntls_session *c = client("localhost", ca_path, "", 1024);
  SSL *s = server(version); link wire = {0};
  if (operation && operation != 5) CHECK(handshake(c, s, &wire) == NTLS_OK);
  uint8_t out[64], payload[32];
  memset(out, 0xa5, sizeof(out)); memset(payload, 0x37, sizeof(payload));
  if (operation == 1 || operation == 4) {
    /* Discard ordinary tickets before measuring a single authenticated read. */
    ntls_result r = nyra_tls_read(c, out, sizeof(out));
    CHECK(!r.error && r.status == NTLS_INPUT);
    if (operation == 4) {
      CHECK(version == TLS1_3_VERSION);
      CHECK(SSL_key_update(s, SSL_KEY_UPDATE_REQUESTED));
      CHECK(SSL_do_handshake(s) == 1);
    }
    size_t sent = 0; CHECK(SSL_write_ex(s, payload, sizeof(payload), &sent) && sent == sizeof(payload));
    for (int i = 0; i < 20000 && (BIO_ctrl_pending(SSL_get_wbio(s)) || wire.size != wire.start); ++i)
      relay(c, s, &wire);
    CHECK(!BIO_ctrl_pending(SSL_get_wbio(s)) && wire.size == wire.start);
  }
  injecting = 1;
  ntls_result result;
  switch (operation) {
    case 0: result = nyra_tls_handshake(c); break;
    case 1: case 4: result = nyra_tls_read(c, out, sizeof(out)); break;
    case 2: result = nyra_tls_write(c, payload, sizeof(payload)); break;
    case 5:
      injecting = 0; result = later_handshake(c, s, &wire); break;
    default: result = nyra_tls_shutdown(c); break;
  }
  injecting = 0;
  CHECK(!fail_at || hits == 1);
  if (result.error) {
    /* Some provider paths discard their error queue before returning failure.
     * They remain terminal Protocol; the first essential allocation in each
     * allocating operation must retain the observable resource classification. */
    int verification_fallback = operation == 5 && fail_at > 1 &&
        (result.error == NTLS_CERTIFICATE || result.error == NTLS_NAME);
    if (result.error != NTLS_RESOURCE && result.error != NTLS_PROTOCOL && !verification_fallback)
      fprintf(stderr, "operation %d allocation %zu: unexpected error %d\n", operation, fail_at, result.error);
    CHECK(result.error == NTLS_RESOURCE || (fail_at > 1 && result.error == NTLS_PROTOCOL) || verification_fallback);
    CHECK(result.count == 0);
    terminal(c);
    for (size_t i = 0; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
  } else {
    /* Optional provider allocations may fail without aborting the operation. */
    if (operation == 0) CHECK(handshake(c, s, &wire) == NTLS_OK);
    else if (operation == 1 || operation == 4) {
      CHECK(result.status == NTLS_COMPLETE && result.count == sizeof(payload));
      CHECK(!memcmp(out, payload, sizeof(payload)));
      for (size_t i = sizeof(payload); i < sizeof(out); ++i) CHECK(out[i] == 0xa5);
    } else if (operation == 2) {
      CHECK(result.status == NTLS_COMPLETE && result.count == sizeof(payload));
      uint8_t received[64]; size_t count = 0;
      for (int i = 0; i < 20000 && !count; ++i) {
        relay(c, s, &wire); ERR_clear_error();
        int rc = SSL_read_ex(s, received, sizeof(received), &count);
        int error = SSL_get_error(s, rc);
        CHECK(rc == 1 || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);
      }
      CHECK(count == sizeof(payload) && !memcmp(received, payload, count));
    }
    finish_shutdown(c, s, &wire);
  }
  nyra_tls_drop(c); SSL_free(s);
  /* Recovery must work in the same provider after the injected failure. */
  verify_handshake(version, "localhost", "");
  OPENSSL_cleanup(); CHECK(!live);
  printf("RESULT %zu %zu %d\n", attempts, hits, result.error);
  return 0;
}
