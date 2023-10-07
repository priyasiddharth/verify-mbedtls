
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

/* int mbedtls_ssl_decrypt_buf(mbedtls_ssl_context const *ssl, */
/*                             mbedtls_ssl_transform *transform, */
/*                             mbedtls_record *record) { */
/*   int r = nd_int(); */
/*   assume(r <= 0); */
/*   return r; */
/* } */
extern mbedtls_ssl_mode_t nd_mbedtls_ssl_mode_t(void);
mbedtls_ssl_mode_t
mbedtls_ssl_get_mode_from_transform(const mbedtls_ssl_transform *transform) {
  mbedtls_ssl_mode_t mode = nd_mbedtls_ssl_mode_t();
  return mode;
}

void ssl_extract_add_data_from_record(unsigned char *add_data,
                                      size_t *add_data_len, mbedtls_record *rec,
                                      mbedtls_ssl_protocol_version tls_version,
                                      size_t taglen) {
  *add_data = nd_size_t();
}

int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx,
                           const unsigned char *input, size_t ilen) {
  sassert(ctx != NULL);
  sassert(sea_is_dereferenceable(input, ilen));
  int r = nd_int();
  assume(r <= 0);
  return r; // Non-deterministically return either success or error.
}

// Mocking for mbedtls_md_hmac_finish
int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
  sassert(ctx != NULL);
  sassert(sea_is_dereferenceable(
      output, MBEDTLS_SSL_MAC_ADD)); // Assume suitable size for output buffer.
  int r = nd_int();
  assume(r <= 0);
  return r; // Non-deterministically return either success or error.};
}

// Mocking for mbedtls_md_hmac_reset
int mbedtls_md_hmac_reset(mbedtls_md_context_t *ctx) {
  int r = nd_int();
  assume(r <= 0);
  return r;
}
