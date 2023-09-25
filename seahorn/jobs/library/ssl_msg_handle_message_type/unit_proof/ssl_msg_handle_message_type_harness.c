#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_handle_message_type(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
void test_mbedtls_ssl_handle_message_type(void) {
  // NOTE: setup the precondition
  // Assume incoming record structure
  // 0 - header
  // 1 - iv
  // 2 - msg (atleast 2 bytes)
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  ssl.transform_out = &transform;
  // setup handshake
  mbedtls_ssl_handshake_params handshake;
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));
  ssl.handshake = &handshake;
  mbedtls_ssl_transform alt_transform;
  memhavoc(&alt_transform, sizeof(mbedtls_ssl_transform));
  ssl.handshake->alt_transform_out = &alt_transform;

  // setup incoming data
  size_t in_buf_len = nd_size_t();
  assume(in_buf_len <= GLOBAL_BUF_MAX_SIZE);
  unsigned char *in_buf = (unsigned char *)malloc(in_buf_len);
  ssl.in_len = (unsigned char *)&in_buf_len;
  // setup inp header
  size_t in_header_start = nd_size_t();
  ssl.in_hdr = in_buf + in_header_start;
  size_t in_header_len = nd_size_t();
  // setup iv
  size_t in_iv_len = nd_size_t();
  ssl.in_iv = in_buf + in_header_len;
  // setup in msg
  ssl.in_msg = in_buf + in_iv_len;
  ssl.in_msglen = nd_size_t();
  assume(ssl.in_msglen >= 2);
  assume(in_header_len <= in_buf_len);
  assume(in_iv_len <= in_buf_len);
  assume(ssl.in_msglen <= in_buf_len);
  assume(in_header_len + in_iv_len + ssl.in_msglen == in_buf_len);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_handle_message_type(&ssl);
  // NOTE: Postcondition check in environment
}

int main(void) {
  test_mbedtls_ssl_handle_message_type();
  return 0;
}
