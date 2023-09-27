#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_handle_pending_alert) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  // setup outgoing data
  size_t out_buf_len = nd_size_t();
  assume(out_buf_len <= GLOBAL_BUF_MAX_SIZE);
  unsigned char *out_buf = (unsigned char *)malloc(out_buf_len);
  ssl.out_len = (unsigned char *)&out_buf_len;
  // setup out header
  size_t out_header_start = nd_size_t();
  ssl.out_hdr = out_buf + out_header_start;
  size_t out_header_len = nd_size_t();
  // setup iv
  size_t out_iv_len = nd_size_t();
  ssl.out_iv = out_buf + out_header_len;
  // setup out msg
  ssl.out_msg = out_buf + out_iv_len;
  ssl.out_msglen = nd_size_t();
  assume(ssl.out_msglen >= 2);
  assume(out_header_len <= out_buf_len);
  assume(out_iv_len <= out_buf_len);
  assume(ssl.out_msglen <= out_buf_len);
  assume(out_header_len + out_iv_len + ssl.out_msglen == out_buf_len);
  // NOTE: call the SUT

  // NOTE: call the SUT
  int rc = mbedtls_ssl_handle_pending_alert(&ssl);
  // NOTE: Postcondition check out environment
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_handle_pending_alert);
  return 0;
}
