/* Private ABI: transport-neutral OpenSSL engine, never exported from tls.ny. */
#ifndef NYRA_TLS_ENGINE_H
#define NYRA_TLS_ENGINE_H
#include <stdint.h>
#include <stddef.h>

typedef struct ntls_session ntls_session;
enum ntls_status { NTLS_COMPLETE, NTLS_INPUT, NTLS_OUTPUT, NTLS_PEER_CLOSED };
enum ntls_error {
  NTLS_OK, NTLS_ARGUMENT, NTLS_TRUST, NTLS_CERTIFICATE, NTLS_NAME,
  NTLS_PROTOCOL, NTLS_EOF, NTLS_CLOSED, NTLS_STATE, NTLS_RESOURCE
};
/* Success/WANT progress is separate from terminal or argument errors. */
typedef struct ntls_result { int32_t status; int32_t error; intptr_t count; } ntls_result;
int32_t nyra_tls_client_new(const uint8_t *peer, intptr_t peer_size,
    const uint8_t *ca_file, intptr_t ca_size, const uint8_t *alpn, intptr_t alpn_size,
    int32_t capacity, ntls_session **out);
void nyra_tls_drop(ntls_session *session);
ntls_result nyra_tls_handshake(ntls_session *session);
ntls_result nyra_tls_read(ntls_session *session, uint8_t *out, intptr_t size);
ntls_result nyra_tls_probe_read(ntls_session *session, uint8_t *out, intptr_t size);
ntls_result nyra_tls_write(ntls_session *session, const uint8_t *data, intptr_t size);
ntls_result nyra_tls_shutdown(ntls_session *session);
ntls_result nyra_tls_feed(ntls_session *session, const uint8_t *data, intptr_t size);
ntls_result nyra_tls_drain(ntls_session *session, uint8_t *out, intptr_t size);
int32_t nyra_tls_end_input(ntls_session *session);
intptr_t nyra_tls_pending_output(ntls_session *session);
ntls_result nyra_tls_alpn(ntls_session *session, uint8_t *out, intptr_t size);
/* Nyra uses explicit out storage to avoid a compiler-specific aggregate return ABI. */
void nyra_tls_step(ntls_session *session, int32_t operation, const uint8_t *input,
    uint8_t *output, intptr_t size, ntls_result *out);
#endif
