#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

int mbedtls_ssl_decrypt_buf(mbedtls_ssl_context const *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *record) {
  int r = nd_int();
  assume(r <= 0);
  return r;
}

int mbedtls_ssl_encrypt_buf(mbedtls_ssl_context *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *rec,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng) {
  int r = nd_int();
  assume(r <= 0);
  return r;
}

int mbedtls_ssl_check_dtls_clihlo_cookie(mbedtls_ssl_context *ssl,
                                         const unsigned char *cli_id,
                                         size_t cli_id_len,
                                         const unsigned char *in, size_t in_len,
                                         unsigned char *obuf, size_t buf_len,
                                         size_t *olen) {
  int r = nd_int();
  assume(r <= 0);
  return r;
}
