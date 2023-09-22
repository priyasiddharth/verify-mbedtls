#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_fetch_input(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
extern int ssl_recv_fn(void *ctx, unsigned char *buf, size_t len);
extern int ssl_get_timer(void *ctx);
extern void set_min_recv_bytes(size_t num_bytes);
void test_mbedtls_ssl_fetch_input(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  // assume(ssl.in_buf_len < GLOBAL_BUF_MAX_SIZE); // bound buffer length
  //
  size_t buf_size = 4096;
  unsigned char *buf = (unsigned char *)malloc(buf_size);
  memhavoc(buf, sizeof(buf_size));
  // assume(buf_size >= ssl.in_left);
  ssl.in_hdr = buf;
  ssl.f_recv_timeout = nd_bool() ? &ssl_recv_fn_timeout : NULL;
  ssl.f_recv = nd_bool() ? &ssl_recv_fn : NULL;
  ssl.f_get_timer = &ssl_get_timer;
  /* mbedtls_ssl_transform transform; */
  /* memhavoc(&transform, sizeof(mbedtls_ssl_transform)); */
  /* ssl.transform_out = &transform; */
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  mbedtls_ssl_handshake_params handshake;
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));
  ssl.handshake = &handshake;
  size_t nb_want = nd_size_t();
  assume(nb_want < MAX_BUFFER_SIZE);
  assume(ssl.in_left < MAX_BUFFER_SIZE);
  // assume a specific memory layout to constrain in_hdr and in_buf start
  // pointers
  assume((ssl.in_hdr - ssl.in_buf > 0) &&
         (ssl.in_hdr - ssl.in_buf <= MBEDTLS_SSL_IN_BUFFER_LEN));
  set_min_recv_bytes(nb_want);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_fetch_input(&ssl, nb_want);
  // NOTE: Postcondition check
  /* * If we return 0, is it guaranteed that (at least) nb_want bytes are */
  /* * available (from this read and/or a previous one). Otherwise, an error
   * code */
  /* * is returned (possibly EOF or WANT_READ). */
  if (rc == 0) {
    sassert(ssl.in_left >= nb_want);
  }
  /* * With stream transport (TLS) on success ssl->in_left == nb_want, but */
  /* * with datagram transport (DTLS) on success ssl->in_left >= nb_want, */
  /* * since we always read a whole datagram at once. */
}

int main(void) {
  test_mbedtls_ssl_fetch_input();
  return 0;
}
