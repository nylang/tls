/* OpenSSL owns cryptography and certificate parsing; no sockets or OS trust lookup here. */
#include "tls_engine.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sslerr.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER != 0x30500090L
#error "Build with the pinned OpenSSL 3.5.9 headers"
#endif

#define NTLS_RECORD 16384
struct ntls_session {
  OSSL_LIB_CTX *provider;
  SSL *ssl;
  BIO *wire;
  int handshaken, closing, failed, input_ended;
  int pending; /* 0 none, 1 read, 2 write; one caller-thread operation at a time. */
  size_t write_size, read_size;
  uint8_t write_retry[NTLS_RECORD];
  uint8_t read_retry[NTLS_RECORD];
};
static ntls_result result(int status, int error, size_t count) {
  ntls_result out = {status, error, (intptr_t)count};
  return out;
}
static ntls_result failure(int error) { return result(NTLS_COMPLETE, error, 0); }
static int range_ok(const void *p, intptr_t size) { return size >= 0 && (p || size == 0); }
static int text_copy(const uint8_t *p, intptr_t size, char *out, size_t capacity) {
  if (!p || size <= 0 || (size_t)size >= capacity || memchr(p, 0, (size_t)size)) return 0;
  memcpy(out, p, (size_t)size); out[size] = 0; return 1;
}
static int dns_name_ok(const char *peer) {
  size_t label = 0;
  const char *p = peer;
  for (; *p; ++p) {
    unsigned char c = (unsigned char)*p;
    if (c == '.') {
      if (!label || p[-1] == '-') return 0;
      label = 0; continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-')) return 0;
    if ((!label && c == '-') || ++label > 63) return 0;
  }
  return label && p[-1] != '-';
}
void nyra_tls_drop(ntls_session *s) {
  if (!s) return;
  SSL_free(s->ssl); BIO_free(s->wire);
  OSSL_LIB_CTX_free(s->provider);
  OPENSSL_cleanse(s->write_retry, sizeof(s->write_retry));
  OPENSSL_cleanse(s->read_retry, sizeof(s->read_retry));
  free(s);
}
int32_t nyra_tls_client_new(const uint8_t *peer, intptr_t peer_size,
    const uint8_t *ca_file, intptr_t ca_size, const uint8_t *alpn, intptr_t alpn_size,
    int32_t capacity, ntls_session **out) {
  char name[254], path[4096];
  SSL_CTX *ctx = NULL;
  OSSL_LIB_CTX *provider = NULL;
  BIO *internal = NULL;
  ntls_session *s = NULL;
  int error = NTLS_RESOURCE;
  if (!out) return NTLS_ARGUMENT;
  *out = NULL;
  if (!text_copy(peer, peer_size, name, sizeof(name)) ||
      !text_copy(ca_file, ca_size, path, sizeof(path)) ||
      !range_ok(alpn, alpn_size) || alpn_size > 255 ||
      capacity < 1024 || capacity > 1048576) return NTLS_ARGUMENT;
  if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) return NTLS_STATE;
  ERR_clear_error();
  /* Failed lazy algorithm registration must not poison another session's cache. */
  provider = OSSL_LIB_CTX_new();
  if (!provider) goto done;
  ctx = SSL_CTX_new_ex(provider, NULL, TLS_client_method());
  if (!ctx) goto done;
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) goto done;
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ctx, 8);
  SSL_CTX_set_max_cert_list(ctx, 262144);
  /* No default paths, SSL_CERT_FILE/SSL_CERT_DIR, or insecure fallback. */
  if (!SSL_CTX_load_verify_file(ctx, path)) { error = NTLS_TRUST; goto done; }
  s = calloc(1, sizeof(*s));
  if (!s) goto done;
  s->provider = provider; provider = NULL;
  s->ssl = SSL_new(ctx);
  if (!s->ssl || !BIO_new_bio_pair(&internal, (size_t)capacity, &s->wire, (size_t)capacity)) goto done;
  SSL_set_bio(s->ssl, internal, internal); internal = NULL;
  X509_VERIFY_PARAM *param = SSL_get0_param(s->ssl);
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
  /* IP identities use iPAddress SAN verification and never emit an IP SNI name. */
  ERR_clear_error();
  if (!X509_VERIFY_PARAM_set1_ip_asc(param, name)) {
    /* The pinned provider reports invalid IP syntax without an error, but
     * allocation failure on a valid IP sets the error queue. Never retry that
     * failure as a DNS identity or accidentally emit IP SNI. */
    if (ERR_peek_error()) goto done;
    if (!dns_name_ok(name)) { error = NTLS_ARGUMENT; goto done; }
    if (!SSL_set1_host(s->ssl, name) || !SSL_set_tlsext_host_name(s->ssl, name)) goto done;
  }
  if (alpn_size) {
    uint8_t protocols[256]; protocols[0] = (uint8_t)alpn_size;
    memcpy(protocols + 1, alpn, (size_t)alpn_size);
    if (SSL_set_alpn_protos(s->ssl, protocols, (unsigned int)alpn_size + 1)) goto done;
  }
  SSL_set_connect_state(s->ssl);
  *out = s; s = NULL; error = NTLS_OK;
done:
  BIO_free(internal); SSL_CTX_free(ctx); nyra_tls_drop(s); OSSL_LIB_CTX_free(provider);
  ERR_clear_error();
  return error;
}
static int available(ntls_session *s) { return s && !s->failed; }
static ntls_result classify(ntls_session *s, int rc, size_t count) {
  /* Must be the first OpenSSL call after the TLS operation, on the same thread. */
  int error = SSL_get_error(s->ssl, rc);
  if (error == SSL_ERROR_NONE) return result(NTLS_COMPLETE, NTLS_OK, count);
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
    /* Flush a generated flight even when OpenSSL itself wants more input. */
    return result(BIO_ctrl_pending(s->wire) ? NTLS_OUTPUT :
        error == SSL_ERROR_WANT_WRITE ? NTLS_OUTPUT : NTLS_INPUT, NTLS_OK, 0);
  }
  if (error == SSL_ERROR_ZERO_RETURN) return result(NTLS_PEER_CLOSED, NTLS_OK, 0);
  long verification = SSL_get_verify_result(s->ssl);
  unsigned long code = 0, next;
  int allocation_failed = verification == X509_V_ERR_OUT_OF_MEM;
  /* A later SSL wrapper error may hide the original provider allocation error. */
  while ((next = ERR_get_error()) != 0) {
    code = next;
    if (ERR_GET_REASON(next) == ERR_R_MALLOC_FAILURE) allocation_failed = 1;
  }
  s->failed = 1;
  if (allocation_failed) return failure(NTLS_RESOURCE);
  if (verification == X509_V_ERR_HOSTNAME_MISMATCH || verification == X509_V_ERR_IP_ADDRESS_MISMATCH)
    return failure(NTLS_NAME);
  if (verification != X509_V_OK) return failure(NTLS_CERTIFICATE);
  if (ERR_GET_LIB(code) == ERR_LIB_SSL && ERR_GET_REASON(code) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
    return failure(NTLS_EOF);
  return failure(NTLS_PROTOCOL);
}
ntls_result nyra_tls_handshake(ntls_session *s) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (s->closing) return failure(NTLS_STATE);
  if (s->handshaken) return result(NTLS_COMPLETE, NTLS_OK, 0);
  ERR_clear_error();
  int rc = SSL_do_handshake(s->ssl);
  ntls_result out = classify(s, rc, 0);
  if (rc == 1) s->handshaken = 1;
  return out;
}
ntls_result nyra_tls_write(ntls_session *s, const uint8_t *data, intptr_t size) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (!s->handshaken || s->closing || s->pending == 1) return failure(NTLS_STATE);
  if (!range_ok(data, size) || size > NTLS_RECORD) return failure(NTLS_ARGUMENT);
  if (s->pending == 2) {
    if ((size_t)size != s->write_size || memcmp(data, s->write_retry, (size_t)size)) return failure(NTLS_STATE);
  } else {
    if (!size) return result(NTLS_COMPLETE, NTLS_OK, 0);
    memcpy(s->write_retry, data, (size_t)size); s->write_size = (size_t)size;
    s->pending = 2;
  }
  size_t written = 0;
  ERR_clear_error();
  int rc = SSL_write_ex(s->ssl, s->write_retry, s->write_size, &written);
  ntls_result out = classify(s, rc, written);
  if (out.error || out.status == NTLS_COMPLETE || out.status == NTLS_PEER_CLOSED) {
    s->pending = 0; OPENSSL_cleanse(s->write_retry, s->write_size); s->write_size = 0;
  }
  return out;
}
ntls_result nyra_tls_read(ntls_session *s, uint8_t *out, intptr_t size) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (!s->handshaken || s->closing || s->pending == 2) return failure(NTLS_STATE);
  if (!range_ok(out, size) || size > NTLS_RECORD) return failure(NTLS_ARGUMENT);
  if (s->pending == 1 && (size_t)size != s->read_size) return failure(NTLS_STATE);
  if (!size) return result(NTLS_COMPLETE, NTLS_OK, 0);
  s->read_size = (size_t)size; s->pending = 1;
  size_t read_size = 0;
  ERR_clear_error();
  int rc = SSL_read_ex(s->ssl, s->read_retry, (size_t)size, &read_size);
  ntls_result progress = classify(s, rc, read_size);
  if (progress.error || progress.status == NTLS_COMPLETE || progress.status == NTLS_PEER_CLOSED) s->pending = 0;
  if (rc == 1) memcpy(out, s->read_retry, read_size);
  return progress;
}
ntls_result nyra_tls_shutdown(ntls_session *s) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (!s->handshaken || s->pending == 2) return failure(NTLS_STATE);
  /* A pending read may be abandoned to initiate protocol shutdown. */
  s->pending = 0; s->closing = 1;
  ERR_clear_error();
  int rc = SSL_shutdown(s->ssl);
  if (rc == 0) return result(BIO_ctrl_pending(s->wire) ? NTLS_OUTPUT : NTLS_INPUT, NTLS_OK, 0);
  return classify(s, rc, 0);
}
ntls_result nyra_tls_feed(ntls_session *s, const uint8_t *data, intptr_t size) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (!range_ok(data, size)) return failure(NTLS_ARGUMENT);
  if (s->input_ended) return failure(NTLS_STATE);
  if (!size) return result(NTLS_COMPLETE, NTLS_OK, 0);
  size_t amount = (size_t)size;
  if (amount > INT_MAX) amount = INT_MAX;
  int count = BIO_write(s->wire, data, (int)amount);
  if (count > 0) return result(NTLS_COMPLETE, NTLS_OK, (size_t)count);
  return BIO_should_retry(s->wire) ? result(NTLS_OUTPUT, NTLS_OK, 0) : failure(NTLS_PROTOCOL);
}
ntls_result nyra_tls_drain(ntls_session *s, uint8_t *out, intptr_t size) {
  if (!s) return failure(NTLS_CLOSED);
  if (!range_ok(out, size)) return failure(NTLS_ARGUMENT);
  if (!size) return result(NTLS_COMPLETE, NTLS_OK, 0);
  size_t amount = (size_t)size;
  if (amount > INT_MAX) amount = INT_MAX;
  int count = BIO_read(s->wire, out, (int)amount);
  if (count > 0) return result(NTLS_COMPLETE, NTLS_OK, (size_t)count);
  return BIO_should_retry(s->wire) ? result(NTLS_INPUT, NTLS_OK, 0) : failure(NTLS_PROTOCOL);
}
int32_t nyra_tls_end_input(ntls_session *s) {
  if (!available(s)) return NTLS_CLOSED;
  if (!s->input_ended) { BIO_shutdown_wr(s->wire); s->input_ended = 1; }
  return NTLS_OK;
}
intptr_t nyra_tls_pending_output(ntls_session *s) { return s ? (intptr_t)BIO_ctrl_pending(s->wire) : 0; }
ntls_result nyra_tls_alpn(ntls_session *s, uint8_t *out, intptr_t size) {
  if (!available(s)) return failure(NTLS_CLOSED);
  if (!s->handshaken) return failure(NTLS_STATE);
  const unsigned char *protocol = NULL;
  unsigned int count = 0;
  SSL_get0_alpn_selected(s->ssl, &protocol, &count);
  if (!range_ok(out, size) || (size_t)size < count) return failure(NTLS_ARGUMENT);
  if (count) memcpy(out, protocol, count);
  return result(NTLS_COMPLETE, NTLS_OK, count);
}

void nyra_tls_step(ntls_session *s, int32_t operation, const uint8_t *input,
    uint8_t *output, intptr_t size, ntls_result *out) {
  if (!out) return;
  switch (operation) {
    case 0: *out = nyra_tls_handshake(s); break;
    case 1: *out = nyra_tls_read(s, output, size); break;
    case 2: *out = nyra_tls_write(s, input, size); break;
    case 3: *out = nyra_tls_shutdown(s); break;
    case 4: *out = nyra_tls_feed(s, input, size); break;
    case 5: *out = nyra_tls_drain(s, output, size); break;
    case 6: *out = nyra_tls_alpn(s, output, size); break;
    default: *out = failure(NTLS_ARGUMENT); break;
  }
}
