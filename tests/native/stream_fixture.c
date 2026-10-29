// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/* Native loopback peer and adapter interposition, linked into acceptance executables only. */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <process.h>
typedef SOCKET test_socket;
typedef int test_socklen;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define test_close closesocket
#define TEST_RESET WSAECONNRESET
#define TEST_WOULD_BLOCK WSAEWOULDBLOCK
static HANDLE server_thread;
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
typedef int test_socket;
typedef socklen_t test_socklen;
#define TEST_INVALID_SOCKET (-1)
#define test_close close
#define TEST_RESET ECONNRESET
#define TEST_WOULD_BLOCK EAGAIN
static pthread_t server_thread;
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl3.h>
#include "net_core_os.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NYRA_TLS_TEST_CERT_FILE
#error "accept.py must supply fixture certificate/key paths"
#endif
static test_socket listener = TEST_INVALID_SOCKET;
static int running, server_mode, expected_bytes, server_result;
static SSL_CTX *server_context;
static atomic_int released, write_limit, write_calls, write_stalls, fail_after;
static atomic_int written_bytes, partial_writes, injected_stalls;
static atomic_int tamper_armed, tamper_header_remaining, tampered_reads;
static atomic_int boundary_target = -1;
static atomic_int boundary_waiting, boundary_released, boundary_timed_out;
static void fixture_pause(void) {
#ifdef _WIN32
  Sleep(1);
#else
  const struct timespec pause = {0, 1000000};
  nanosleep(&pause, NULL);
#endif
}
/* Test-only rendezvous after successful native I/O, before returning to Poll.
 * The worker only cancels a public token; it never accesses stream state. */
static void boundary_pause(int direction, int32_t code, intptr_t count) {
  int expected = direction;
  int reached = direction == 2 ? code != 0 : !code && count > 0;
  if (!reached || !atomic_compare_exchange_strong(&boundary_target, &expected, -1)) return;
  atomic_store(&boundary_waiting, 1);
  for (int i = 0; i < 10000 && !atomic_load(&boundary_released); ++i) fixture_pause();
  if (!atomic_load(&boundary_released)) atomic_store(&boundary_timed_out, 1);
}
void nyra_tls_test_boundary_arm(int32_t direction) {
  atomic_store(&boundary_waiting, 0); atomic_store(&boundary_released, 0);
  atomic_store(&boundary_timed_out, 0); atomic_store(&boundary_target, direction);
}
int32_t nyra_tls_test_boundary_wait(void) {
  for (int i = 0; i < 5000 && !atomic_load(&boundary_waiting); ++i) fixture_pause();
  return atomic_load(&boundary_waiting);
}
void nyra_tls_test_boundary_release(void) { atomic_store(&boundary_released, 1); }
int32_t nyra_tls_test_boundary_hit(void) {
  return atomic_load(&boundary_timed_out) ? -1 : atomic_load(&boundary_waiting);
}

#ifdef _WIN32
static INIT_ONCE winsock_once = INIT_ONCE_STATIC_INIT;
static void fixture_winsock_cleanup(void) { WSACleanup(); }
static BOOL CALLBACK fixture_winsock_init(PINIT_ONCE once, PVOID parameter, PVOID *context) {
  (void)once; (void)parameter; (void)context;
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data)) return FALSE;
  /* Match net_core's Windows acceptance fixture: retain one provider reference
   * until exit rather than measuring asynchronous provider unload/reload. */
  if (!CompareStringEx(LOCALE_NAME_INVARIANT, 0, L"a", 1, L"b", 1, NULL, NULL, 0) ||
      atexit(fixture_winsock_cleanup)) { WSACleanup(); return FALSE; }
  return TRUE;
}
#endif

int32_t nyra_tls_test_real_write(intptr_t, const uint8_t *, intptr_t, intptr_t *, nc_error *);
int32_t nyra_tls_test_real_read(intptr_t, uint8_t *, intptr_t, intptr_t *, nc_error *);
int32_t net_core_os_read(intptr_t handle, uint8_t *data, intptr_t size, intptr_t *out, nc_error *error) {
  int32_t code = nyra_tls_test_real_read(handle, data, size, out, error);
  if (!code && *out > 0 && atomic_load(&tamper_armed)) {
    intptr_t skip = atomic_load(&tamper_header_remaining);
    if (skip > *out) skip = *out;
    atomic_fetch_sub(&tamper_header_remaining, (int)skip);
    if (*out > skip) {
      /* Preserve the five-byte TLS header; alter one encrypted payload byte. */
      data[skip] ^= 1;
      atomic_store(&tamper_armed, 0); atomic_fetch_add(&tampered_reads, 1);
    }
  }
  boundary_pause(0, code, *out);
  return code;
}
void nyra_tls_test_arm_tamper(void) {
  atomic_store(&tamper_header_remaining, 5); atomic_store(&tamper_armed, 1);
  atomic_store(&released, 1);
}
int32_t nyra_tls_test_tampered_reads(void) { return atomic_load(&tampered_reads); }
int32_t net_core_os_write(intptr_t handle, const uint8_t *data, intptr_t size, intptr_t *out, nc_error *error) {
  int call = atomic_fetch_add(&write_calls, 1) + 1;
  *out = 0;
  int fail = atomic_load(&fail_after);
  int sent = atomic_load(&written_bytes);
  if (fail >= 0 && sent >= fail) {
    error->kind = NC_RESET; error->native_code = TEST_RESET;
    boundary_pause(2, NC_RESET, 0); return NC_RESET;
  }
  int stalls = atomic_load(&write_stalls);
  if (stalls && call % stalls == 0) {
    atomic_fetch_add(&injected_stalls, 1);
    error->kind = NC_WOULD_BLOCK; error->native_code = TEST_WOULD_BLOCK; return NC_WOULD_BLOCK;
  }
  intptr_t amount = size;
  int limit = atomic_load(&write_limit);
  if (limit > 0 && amount > limit) amount = limit;
  if (fail >= 0 && amount > fail - sent) amount = fail - sent;
  int32_t rc = nyra_tls_test_real_write(handle, data, amount, out, error);
  if (!rc) {
    atomic_fetch_add(&written_bytes, (int)*out);
    if (*out < size) atomic_fetch_add(&partial_writes, 1);
  }
  boundary_pause(1, rc, *out);
  return rc;
}
void nyra_tls_test_write_controls(int32_t limit, int32_t stalls, int32_t fail) {
  atomic_store(&write_limit, limit); atomic_store(&write_stalls, stalls); atomic_store(&fail_after, fail);
  atomic_store(&write_calls, 0); atomic_store(&written_bytes, 0);
  atomic_store(&partial_writes, 0); atomic_store(&injected_stalls, 0);
}
int32_t nyra_tls_test_partial_writes(void) { return atomic_load(&partial_writes); }
int32_t nyra_tls_test_write_stalls(void) { return atomic_load(&injected_stalls); }
static void wait_release_level(int level) {
  for (int i = 0; i < 10000 && atomic_load(&released) < level; ++i) {
#ifdef _WIN32
    Sleep(1);
#else
    const struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
#endif
  }
}
static void wait_release(void) { wait_release_level(1); }
static void received_key_update(int writing, int version, int type, const void *buffer,
    size_t size, SSL *ssl, void *argument) {
  (void)version; (void)ssl;
  if (!writing && type == SSL3_RT_HANDSHAKE && size == 5 &&
      ((const uint8_t *)buffer)[0] == SSL3_MT_KEY_UPDATE) {
    int *count = argument;
    if (((const uint8_t *)buffer)[4] != SSL_KEY_UPDATE_NOT_REQUESTED) *count = -100;
    else ++*count;
  }
}
#ifdef _WIN32
static unsigned __stdcall serve(void *unused) {
#else
static void *serve(void *unused) {
#endif
  (void)unused;
  test_socket fd = accept(listener, NULL, NULL);
  if (fd == TEST_INVALID_SOCKET) { server_result = -1; return 0; }
#ifdef SO_NOSIGPIPE
  int enabled = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
#ifdef _WIN32
  DWORD timeout = 10000;
#else
  struct timeval timeout = {10, 0};
#endif
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
  if (server_mode == 1) { wait_release(); test_close(fd); return 0; }
  SSL *ssl = SSL_new(server_context);
  if (!ssl || !SSL_set_fd(ssl, (int)fd)) { server_result = -2; SSL_free(ssl); test_close(fd); return 0; }
  if (SSL_accept(ssl) != 1) {
    server_result = server_mode == 5 ? 0 : -3;
    SSL_free(ssl); test_close(fd); return 0;
  }
  if (server_mode == 3) { wait_release(); SSL_free(ssl); test_close(fd); return 0; }
  if (server_mode == 7) {
    wait_release();
    size_t sent = 0;
    if (!SSL_write_ex(ssl, "forged", 6, &sent) || sent != 6) server_result = -9;
    /* Keep TCP live until the client has classified the altered TLS record. */
    wait_release_level(2); SSL_free(ssl); test_close(fd); return 0;
  }
  int key_updates = 0;
  if (server_mode == 6) {
    SSL_set_msg_callback(ssl, received_key_update); SSL_set_msg_callback_arg(ssl, &key_updates);
    size_t sent = 0;
    if (!SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED) ||
        !SSL_write_ex(ssl, "key-update", 10, &sent) || sent != 10) {
      server_result = -10; SSL_free(ssl); test_close(fd); return 0;
    }
  }
  if (server_mode == 2) {
    size_t sent = 0;
    if (!SSL_write_ex(ssl, "prefix", 6, &sent) || sent != 6) server_result = -4;
    SSL_free(ssl); test_close(fd); return 0;
  }
  uint8_t *payload = malloc((size_t)expected_bytes + 1);
  if (!payload) { server_result = -5; SSL_free(ssl); test_close(fd); return 0; }
  size_t total = 0;
  while (total < (size_t)expected_bytes) {
    size_t count = 0;
    if (!SSL_read_ex(ssl, payload + total, (size_t)expected_bytes - total, &count) || !count) { server_result = -6; goto done; }
    total += count;
  }
  if (server_mode == 6 && key_updates != 1) { server_result = -11; goto done; }
  total = 0;
  while (total < (size_t)expected_bytes) {
    size_t size = (size_t)expected_bytes - total; if (size > 317) size = 317;
    size_t count = 0;
    if (!SSL_write_ex(ssl, payload + total, size, &count) || !count) { server_result = -7; goto done; }
    total += count;
  }
  int rc = SSL_shutdown(ssl);
  if (rc == 0) rc = SSL_shutdown(ssl);
  if (rc != 1) server_result = -8;
done:
  free(payload); SSL_free(ssl); test_close(fd); return 0;
}
int32_t nyra_tls_test_server_start(int32_t mode, int32_t size) {
  if (running || size < 0 || size > 1048576) return -1;
  nyra_tls_test_write_controls(0, 0, -1);
  nyra_tls_test_boundary_arm(-1);
  atomic_store(&tamper_armed, 0); atomic_store(&tampered_reads, 0);
#ifdef _WIN32
  if (!InitOnceExecuteOnce(&winsock_once, fixture_winsock_init, NULL, NULL)) return -2;
#else
  signal(SIGPIPE, SIG_IGN);
#endif
  server_context = SSL_CTX_new(TLS_server_method());
  if (!server_context) goto failed;
  if (!SSL_CTX_set_min_proto_version(server_context, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version(server_context, TLS1_3_VERSION) ||
      /* Close tests abort immediately after the client's Finished. Avoid
       * unrelated post-handshake tickets racing that abort on WinSock. */
      !SSL_CTX_set_num_tickets(server_context, 0) ||
      !SSL_CTX_use_certificate_chain_file(server_context, NYRA_TLS_TEST_CERT_FILE) ||
      !SSL_CTX_use_PrivateKey_file(server_context, NYRA_TLS_TEST_KEY_FILE, SSL_FILETYPE_PEM)) goto failed;
  listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener == TEST_INVALID_SOCKET) goto failed;
  struct sockaddr_in address; memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  test_socklen length = sizeof(address);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 8) ||
      getsockname(listener, (struct sockaddr *)&address, &length)) { goto failed; }
  server_mode = mode; expected_bytes = size; server_result = 0; atomic_store(&released, 0);
#ifdef _WIN32
  server_thread = (HANDLE)_beginthreadex(NULL, 0, serve, NULL, 0, NULL);
  if (!server_thread) goto failed;
#else
  if (pthread_create(&server_thread, NULL, serve, NULL)) goto failed;
#endif
  running = 1;
  return ntohs(address.sin_port);
failed:
  if (listener != TEST_INVALID_SOCKET) { test_close(listener); listener = TEST_INVALID_SOCKET; }
  SSL_CTX_free(server_context); server_context = NULL; return -3;
}
int32_t nyra_tls_test_server_join(void) {
  if (!running) return -1;
  atomic_store(&released, 2);
#ifdef _WIN32
  WaitForSingleObject(server_thread, INFINITE);
  CloseHandle(server_thread);
#else
  pthread_join(server_thread, NULL);
#endif
  test_close(listener); listener = TEST_INVALID_SOCKET;
  SSL_CTX_free(server_context); server_context = NULL; running = 0;
  if (server_result) fprintf(stderr, "TLS fixture server result=%d\n", server_result);
  return server_result;
}
int32_t nyra_tls_test_fd_count(void) {
#ifdef _WIN32
  DWORD count = 0;
  return GetProcessHandleCount(GetCurrentProcess(), &count) ? (int32_t)count : -1;
#else
#ifdef __APPLE__
  DIR *directory = opendir("/dev/fd");
#else
  DIR *directory = opendir("/proc/self/fd");
#endif
  if (!directory) return -1;
  int count = 0; struct dirent *entry;
  while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
  closedir(directory); return count;
#endif
}
int32_t nyra_tls_test_reset_native_code(void) { return TEST_RESET; }
int32_t nyra_tls_test_written_bytes(void) { return atomic_load(&written_bytes); }
