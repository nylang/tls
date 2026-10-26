/* Only the Nyra acceptance executable links this fixture-owned immutable path. */
#include <stdint.h>
#include <string.h>
#ifndef NYRA_TLS_TEST_CA_FILE
#error "accept.py must specify the generated local CA file"
#endif
const int8_t *nyra_tls_test_ca_file(void) { return (const int8_t *)NYRA_TLS_TEST_CA_FILE; }
int32_t nyra_tls_test_ca_size(void) { return (int32_t)strlen(NYRA_TLS_TEST_CA_FILE); }
