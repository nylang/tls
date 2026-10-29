// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/* Force-included only into a separately compiled acceptance bridge object. */
#ifndef NYRA_TLS_RESOURCE_HOOKS_H
#define NYRA_TLS_RESOURCE_HOOKS_H
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sslerr.h>
#include <stdlib.h>

OSSL_LIB_CTX *nyra_tls_test_provider_new(void);
void nyra_tls_test_provider_free(OSSL_LIB_CTX *provider);
SSL_CTX *nyra_tls_test_ctx_new(OSSL_LIB_CTX *provider, const char *properties, const SSL_METHOD *method);
void nyra_tls_test_ctx_free(SSL_CTX *context);
int nyra_tls_test_trust(SSL_CTX *context, const char *path);
void *nyra_tls_test_calloc(size_t count, size_t size);
void nyra_tls_test_free(void *pointer);
SSL *nyra_tls_test_ssl_new(SSL_CTX *context);
void nyra_tls_test_ssl_free(SSL *ssl);
int nyra_tls_test_pair(BIO **left, size_t left_size, BIO **right, size_t right_size);
int nyra_tls_test_bio_free(BIO *bio);
void nyra_tls_test_set_bio(SSL *ssl, BIO *read, BIO *write);
int nyra_tls_test_host(SSL *ssl, const char *name);
int nyra_tls_test_ip(X509_VERIFY_PARAM *parameters, const char *name);
long nyra_tls_test_ctrl(SSL *ssl, int command, long argument, void *pointer);
int nyra_tls_test_alpn(SSL *ssl, const unsigned char *protocols, unsigned int size);

#ifdef NYRA_TLS_TEST_RESOURCE_INJECTION
#define OSSL_LIB_CTX_new nyra_tls_test_provider_new
#define OSSL_LIB_CTX_free nyra_tls_test_provider_free
#define SSL_CTX_new_ex nyra_tls_test_ctx_new
#define SSL_CTX_free nyra_tls_test_ctx_free
#define SSL_CTX_load_verify_file nyra_tls_test_trust
#define calloc nyra_tls_test_calloc
#define free nyra_tls_test_free
#define SSL_new nyra_tls_test_ssl_new
#define SSL_free nyra_tls_test_ssl_free
#define BIO_new_bio_pair nyra_tls_test_pair
#define BIO_free nyra_tls_test_bio_free
#define SSL_set_bio nyra_tls_test_set_bio
#define SSL_set1_host nyra_tls_test_host
#define X509_VERIFY_PARAM_set1_ip_asc nyra_tls_test_ip
#define SSL_ctrl nyra_tls_test_ctrl
#define SSL_set_alpn_protos nyra_tls_test_alpn
#endif
#endif
