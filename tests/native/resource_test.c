// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/* Constructor fault injection observes bridge-owned resources, not provider heaps. */
#include "resource_hooks.h"
#include "tls_engine.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
enum fault { FAULT_CONTEXT = 1, FAULT_TRUST, FAULT_STATE, FAULT_SESSION, FAULT_PAIR, FAULT_PARTIAL_PAIR, FAULT_HOST, FAULT_IP, FAULT_SNI, FAULT_ALPN, FAULT_PROVIDER };
static int selected, hits, contexts, sessions, states, bios, host_calls, sni_calls, providers;
static int fail(int point) {
  if (selected != point) return 0;
  selected = 0; ++hits;
  ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
  return 1;
}
OSSL_LIB_CTX *nyra_tls_test_provider_new(void) {
  if (fail(FAULT_PROVIDER)) return NULL;
  OSSL_LIB_CTX *value = OSSL_LIB_CTX_new(); if (value) ++providers; return value;
}
void nyra_tls_test_provider_free(OSSL_LIB_CTX *provider) {
  if (provider) { CHECK(providers > 0); --providers; } OSSL_LIB_CTX_free(provider);
}
SSL_CTX *nyra_tls_test_ctx_new(OSSL_LIB_CTX *provider, const char *properties, const SSL_METHOD *method) {
  if (fail(FAULT_CONTEXT)) return NULL;
  SSL_CTX *value = SSL_CTX_new_ex(provider, properties, method); if (value) ++contexts; return value;
}
void nyra_tls_test_ctx_free(SSL_CTX *context) {
  if (context) { CHECK(contexts > 0); --contexts; } SSL_CTX_free(context);
}
int nyra_tls_test_trust(SSL_CTX *context, const char *path) {
  return fail(FAULT_TRUST) ? 0 : SSL_CTX_load_verify_file(context, path);
}
void *nyra_tls_test_calloc(size_t count, size_t size) {
  if (fail(FAULT_STATE)) return NULL;
  void *value = calloc(count, size); if (value) ++states; return value;
}
void nyra_tls_test_free(void *pointer) {
  if (pointer) { CHECK(states > 0); --states; } free(pointer);
}
SSL *nyra_tls_test_ssl_new(SSL_CTX *context) {
  if (fail(FAULT_SESSION)) return NULL;
  SSL *value = SSL_new(context); if (value) ++sessions; return value;
}
void nyra_tls_test_ssl_free(SSL *ssl) {
  if (ssl) { CHECK(sessions > 0); --sessions; } SSL_free(ssl);
}
int nyra_tls_test_pair(BIO **left, size_t left_size, BIO **right, size_t right_size) {
  if (fail(FAULT_PAIR)) return 0;
  int code = BIO_new_bio_pair(left, left_size, right, right_size);
  if (code) bios += 2;
  /* Also exercise rollback with both endpoints acquired but not yet adopted. */
  return code && fail(FAULT_PARTIAL_PAIR) ? 0 : code;
}
int nyra_tls_test_bio_free(BIO *bio) {
  if (bio) { CHECK(bios > 0); --bios; } return BIO_free(bio);
}
void nyra_tls_test_set_bio(SSL *ssl, BIO *read, BIO *write) {
  CHECK(read && read == write && bios >= 2);
  --bios; /* SSL now owns this endpoint and frees it through SSL_free. */
  SSL_set_bio(ssl, read, write);
}
int nyra_tls_test_host(SSL *ssl, const char *name) {
  ++host_calls; return fail(FAULT_HOST) ? 0 : SSL_set1_host(ssl, name);
}
int nyra_tls_test_ip(X509_VERIFY_PARAM *parameters, const char *name) {
  return fail(FAULT_IP) ? 0 : X509_VERIFY_PARAM_set1_ip_asc(parameters, name);
}
long nyra_tls_test_ctrl(SSL *ssl, int command, long argument, void *pointer) {
  if (command == SSL_CTRL_SET_TLSEXT_HOSTNAME) {
    ++sni_calls; if (fail(FAULT_SNI)) return 0;
  }
  return SSL_ctrl(ssl, command, argument, pointer);
}
int nyra_tls_test_alpn(SSL *ssl, const unsigned char *protocols, unsigned int size) {
  return fail(FAULT_ALPN) ? 1 : SSL_set_alpn_protos(ssl, protocols, size);
}
static void empty(void) { CHECK(!contexts && !sessions && !states && !bios && !providers); }
static int construct(const char *name, const char *ca, ntls_session **out) {
  return nyra_tls_client_new((const uint8_t *)name, (intptr_t)strlen(name),
      (const uint8_t *)ca, (intptr_t)strlen(ca), (const uint8_t *)"http/1.1", 8, 1024, out);
}
int main(int argc, char **argv) {
  CHECK(argc == 2 || argc == 3);
  struct scenario { int point, expected; const char *name, *label; } cases[] = {
    {FAULT_CONTEXT, NTLS_RESOURCE, "localhost", "TLS context allocation failure rolls back"},
    {FAULT_TRUST, NTLS_TRUST, "localhost", "trust loading failure rolls back"},
    {FAULT_STATE, NTLS_RESOURCE, "localhost", "bridge state allocation failure rolls back"},
    {FAULT_SESSION, NTLS_RESOURCE, "localhost", "TLS session allocation failure rolls back"},
    {FAULT_PAIR, NTLS_RESOURCE, "localhost", "BIO pair creation failure rolls back"},
    {FAULT_PARTIAL_PAIR, NTLS_RESOURCE, "localhost", "unadopted BIO endpoints both roll back"},
    {FAULT_HOST, NTLS_RESOURCE, "localhost", "DNS verification allocation failure is ResourceExhausted"},
    {FAULT_IP, NTLS_RESOURCE, "127.0.0.1", "IPv4 verification allocation failure cannot fall back to DNS/SNI"},
    {FAULT_IP, NTLS_RESOURCE, "::1", "IPv6 verification allocation failure cannot fall back to DNS/SNI"},
    {FAULT_SNI, NTLS_RESOURCE, "localhost", "SNI allocation failure is ResourceExhausted"},
    {FAULT_ALPN, NTLS_RESOURCE, "localhost", "ALPN allocation failure rolls back"},
    {FAULT_PROVIDER, NTLS_RESOURCE, "localhost", "private provider context allocation failure rolls back"},
  };
  int only = argc == 3 ? atoi(argv[2]) : -1;
  CHECK(only >= -1 && only < (int)(sizeof(cases) / sizeof(cases[0])));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    if (only >= 0 && i != (size_t)only) continue;
    for (int repeat = 0; repeat < 8; ++repeat) {
      empty(); selected = cases[i].point; hits = host_calls = sni_calls = 0;
      ntls_session *session = (ntls_session *)(uintptr_t)1;
      int code = construct(cases[i].name, argv[1], &session);
      if (code != cases[i].expected) fprintf(stderr, "%s: got %d expected %d\n", cases[i].label, code, cases[i].expected);
      CHECK(code == cases[i].expected && !session && hits == 1 && !selected);
      if (cases[i].point == FAULT_IP) CHECK(!host_calls && !sni_calls);
      empty(); CHECK(!ERR_peek_error());
      host_calls = sni_calls = 0;
      CHECK(construct(cases[i].name, argv[1], &session) == NTLS_OK && session);
      if (cases[i].point == FAULT_IP) CHECK(!host_calls && !sni_calls);
      CHECK(contexts == 0 && sessions == 1 && states == 1 && bios == 1 && providers == 1);
      nyra_tls_drop(session); empty(); CHECK(!ERR_peek_error());
    }
    printf("PASS %s\n", cases[i].label);
  }
  return 0;
}
