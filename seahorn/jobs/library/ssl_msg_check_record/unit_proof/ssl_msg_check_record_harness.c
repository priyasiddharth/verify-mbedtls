#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

#include <stddef.h>

void test_mbedtls_ssl_check_record(void);

void test_mbedtls_ssl_check_record(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  size_t buflen = nd_size_t();
  // TODO: change to malloc_can_fail
  unsigned char *buf = (unsigned char *)malloc(buflen);
  memhavoc(buf, buflen);
  uint8_t transport_type = conf.transport;
  // NOTE: call the SUT
  int rc = mbedtls_ssl_check_record(&ssl, buf, buflen);
  if (transport_type == MBEDTLS_SSL_TRANSPORT_STREAM) {
    sassert(rc == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);
  }

  /* // NOTE: postcondition check */
  /* size_t sentinel_byte_idx = nd_size_t(); */
  /* assume(sentinel_byte_idx < buflen); */
  /* char sentinel_byte = *(((char *)buf) + sentinel_byte_idx); */
  /* sassert(sentinel_byte == 0); */
  /* // TODO: add no UAF check */
}

int main(void) {
  test_mbedtls_ssl_check_record();
  return 0;
}
