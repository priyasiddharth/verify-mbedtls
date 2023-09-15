#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_util.h>

#include <stddef.h>

void test_mbedtls_ssl_flush_output(void);
int send_fn(void *ctx, const unsigned char *buf, size_t len);

void test_mbedtls_ssl_flush_output(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  assume(ssl.out_left < 42); // bound number of bytes to [0, 42)
  size_t buf_size = nd_size_t();
  assume(buf_size >= ssl.out_left);
  unsigned char *buf = (unsigned char *)malloc(buf_size);
  // TODO: why can't we assume bug and send_fn?
  ssl.out_hdr = buf;
  ssl.f_send = &send_fn;
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  assume(ssl.transform_out == &transform);
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  conf.transport = nd_uint8_t();
  assume(ssl.conf = &conf);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_flush_output(&ssl);
}

int main(void) {
  test_mbedtls_ssl_flush_output();
  return 0;
}
