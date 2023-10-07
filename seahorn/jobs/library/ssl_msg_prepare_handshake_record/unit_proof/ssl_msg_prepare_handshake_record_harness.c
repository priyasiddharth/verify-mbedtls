#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_prepare_handshake_record) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup incoming data
  init_incoming_buf(&ssl);
  assume(ssl.in_msglen >= 5);
  unsigned char alert_type = nd_uchar();
  int alert_reason = nd_int();
  // NOTE: call the SUT
  int rc = mbedtls_ssl_prepare_handshake_record(&ssl);
  // NOTE: Postcondition check
  sassert(incoming_buf_valid(&ssl));
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_prepare_handshake_record);
  return 0;
}
