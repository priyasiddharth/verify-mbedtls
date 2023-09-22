#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_finish_handshake_msg(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
extern int ssl_recv_fn(void *ctx, unsigned char *buf, size_t len);
extern int ssl_get_timer(void *ctx);
extern void set_min_recv_bytes(size_t num_bytes);
extern void set_msg_len(size_t);

void test_mbedtls_ssl_finish_handshake_msg(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  // assume(ssl.in_buf_len < GLOBAL_BUF_MAX_SIZE); // bound buffer length
  //
  size_t buf_size = GLOBAL_BUF_MAX_SIZE;
  unsigned char *buf = (unsigned char *)malloc(buf_size);
  memhavoc(buf, sizeof(buf_size));
  ssl.out_msg = buf;
  // assume(buf_size >= ssl.in_left);
  /* ssl.in_hdr = buf; */
  /* ssl.f_recv_timeout = nd_bool() ? &ssl_recv_fn_timeout : NULL; */
  /* ssl.f_recv = nd_bool() ? &ssl_recv_fn : NULL; */
  /* ssl.f_get_timer = &ssl_get_timer; */
  /* /\* mbedtls_ssl_transform transform; *\/ */
  /* /\* memhavoc(&transform, sizeof(mbedtls_ssl_transform)); *\/ */
  /* /\* ssl.transform_out = &transform; *\/ */
  /* struct mbedtls_ssl_config conf; */
  /* memhavoc(&conf, sizeof(mbedtls_ssl_config)); */
  /* ssl.conf = &conf; */
  /* mbedtls_ssl_handshake_params handshake; */
  /* memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params)); */
  /* ssl.handshake = &handshake; */

  size_t buf_len = nd_size_t();
  size_t msg_len = nd_size_t();
  set_msg_len(msg_len);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_finish_handshake_msg(&ssl, buf_len, msg_len);
  // NOTE: Postcondition check in environment
}

int main(void) {
  test_mbedtls_ssl_finish_handshake_msg();
  return 0;
}
