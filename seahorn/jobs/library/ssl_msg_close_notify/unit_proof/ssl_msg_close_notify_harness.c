#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>

#include <stddef.h>

void test_mbedtls_ssl_close_notify(void);

void test_mbedtls_ssl_close_notify(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  assume(ssl.conf == &conf);
  // assume ssl handshake is over
  assume(ssl.state >= MBEDTLS_SSL_HANDSHAKE_OVER);
  unsigned char out_msg_arr[2];
  memhavoc(out_msg_arr, sizeof(2));
  assume(ssl.out_msg == out_msg_arr);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_close_notify(&ssl);
  // NOTE: postcondition check present in the environment.
}

int main(void) {
  test_mbedtls_ssl_close_notify();
  return 0;
}
