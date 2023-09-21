#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

#include <stddef.h>

void test_mbedtls_ssl_dtls_replay_update(void);

void test_mbedtls_ssl_dtls_replay_update(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  // contains 64-bit incoming message
  unsigned char *in_ctr = (unsigned char *)malloc(8);
  memhavoc(in_ctr, 8);
  ssl.in_ctr = in_ctr;
  mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  // NOTE: call the SUT
  mbedtls_ssl_dtls_replay_update(&ssl);
  // NOTE: postcondition check
}

int main(void) {
  test_mbedtls_ssl_dtls_replay_update();
  return 0;
}
