#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

#include <stddef.h>

void test_mbedtls_ssl_buffering_free(void);

void test_mbedtls_ssl_buffering_free(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  mbedtls_ssl_handshake_params handshake;
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));
  ssl.handshake = &handshake;
  // For each execution, record buffer validity for postcondition check
  // NOTE: we need to record buffer validity since zeroise erases validity bit.
  bool is_buf_valid[MBEDTLS_SSL_MAX_BUFFERED_HS];
  // initialize buffers
  for (unsigned slot = 0; slot < MBEDTLS_SSL_MAX_BUFFERED_HS; slot++) {
    mbedtls_ssl_hs_buffer *const hs_buf = &handshake.buffering.hs[slot];
    assume(hs_buf->data_len < GLOBAL_BUF_MAX_SIZE);

    // allocate memory to buffer
    is_buf_valid[slot] = hs_buf->is_valid;
    // TODO: Change to malloc_can_fail
    hs_buf->data = malloc(hs_buf->data_len);
    if (hs_buf->data != NULL) {
      sassert(sea_is_dereferenceable(hs_buf->data, hs_buf->data_len));
    }
    memhavoc(hs_buf->data, hs_buf->data_len);
  }
  // NOTE: call the SUT
  mbedtls_ssl_buffering_free(&ssl);
  // NOTE: postcondition check
  for (unsigned slot = 0; slot < MBEDTLS_SSL_MAX_BUFFERED_HS; slot++) {
    if (is_buf_valid[slot] == 1) {
      // Check that an esrtwhile  *valid* hs_buf is always zeroised
      mbedtls_ssl_hs_buffer *const hs_buf = &handshake.buffering.hs[slot];
      size_t sentinel_byte_idx = nd_size_t();
      assume(sentinel_byte_idx < sizeof(mbedtls_ssl_hs_buffer));
      char sentinel_byte = *(((char *)hs_buf) + sentinel_byte_idx);
      sassert(sentinel_byte == 0);
    }
  }
  // TODO: add no UAF check
}

int main(void) {
  test_mbedtls_ssl_buffering_free();
  return 0;
}
