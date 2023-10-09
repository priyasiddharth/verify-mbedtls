#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_write_change_cipher_spec) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup transform
  /* mbedtls_ssl_transform transform; */
  /* memhavoc(&transform, sizeof(mbedtls_ssl_transform)); */
  /* assume(transform.maclen <= GLOBAL_BUF_MAX_SIZE); */
  /* mbedtls_record rec; */
  /* memhavoc(&rec, sizeof(mbedtls_record)); */
  /* assume(rec.data_len == REC_DATA_LEN); */
  /* rec.buf = (unsigned char *)malloc(GLOBAL_BUF_MAX_SIZE); */
  /* rec.buf_len = GLOBAL_BUF_MAX_SIZE; */
  /* rec.data_offset = 0; */
  /* assume((transform.ivlen - (rec.data_len + 1) % transform.ivlen) <= */
  /*        MAX_PAD_LEN); */
  /* assume(transform.maclen <= GLOBAL_BUF_MAX_SIZE); */
  /* assume(rec.data_len + transform.maclen <= GLOBAL_BUF_MAX_SIZE); */
  /* sea_printf("transform.ivlen:%d", transform.ivlen); */
  /* sea_printf("padlen:%d", */
  /*            transform.ivlen - (rec.data_len + 1) % transform.ivlen); */
  // setup incoming & outgoing data
  init_incoming_buf(&ssl);
  init_outgoing_buf(&ssl);
  assume(ssl.out_msglen >= 12 /* for write_handshake_msg */);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_write_change_cipher_spec(&ssl);
  // NOTE: Postcondition check in env
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_change_cipher_spec);
  return 0;
}
