#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_get_record_expansion(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
void test_mbedtls_ssl_get_record_expansion(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  ssl.transform_out = &transform;
  struct mbedtls_cipher_context_t cipher_ctx;
  memhavoc(&cipher_ctx, sizeof(struct mbedtls_cipher_context_t));
  struct mbedtls_cipher_info_t cipher_info;
  memhavoc(&cipher_info, sizeof(struct mbedtls_cipher_info_t));
  cipher_ctx.cipher_info = &cipher_info;
  ssl.transform_out->cipher_ctx_enc = cipher_ctx;
  // NOTE: call the SUT
  int rc = mbedtls_ssl_get_record_expansion(&ssl);
  // NOTE: Postcondition check in environment
}

int main(void) {
  test_mbedtls_ssl_get_record_expansion();
  return 0;
}
