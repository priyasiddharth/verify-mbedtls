#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_util.h>

void zeroise_and_free(void *buf, size_t len) {
  sassert(sea_is_dereferenceable(buf, len));
}

int ssl_parse_record_header(mbedtls_ssl_context const *ssl, unsigned char *buf,
                            size_t len, mbedtls_record *rec) {
  sassert(sea_is_dereferenceable(buf, len));
  return nd_int();
}

int mbedtls_ssl_decrypt_buf(mbedtls_ssl_context const *ssl,
                            mbedtls_ssl_transform *t, mbedtls_record *r) {
  return nd_int();
}
