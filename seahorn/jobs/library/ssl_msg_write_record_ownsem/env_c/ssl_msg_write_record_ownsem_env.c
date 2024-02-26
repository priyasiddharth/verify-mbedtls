#include "common.h" // allow access to private members of ssl_context
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

extern void sea_tracking_on(void);
extern void sea_tracking_off(void);

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
  if (r == 0) {
    size_t count; 
    count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(rec->buf));
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *)rec->buf, ++count);
    SEA_READ_CACHE(count, rec->buf);
    SEA_WRITE_CACHE(rec->buf, ++count);
  }
  size_t in_data_offset = rec->data_offset;
  rec->data_offset = nd_bool() ? in_data_offset : 0;
  SEA_DIE(rec->buf);
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
