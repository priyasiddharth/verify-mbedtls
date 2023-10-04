#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_write_record) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  ssl.transform_out = &transform;
  // setup incoming & outgoing data
  init_incoming_buf(&ssl);
  init_outgoing_buf(&ssl);
  int force_flush = nd_int();
  // NOTE: call the SUT
  int rc = mbedtls_ssl_write_record(&ssl, force_flush);
  // NOTE: Postcondition check
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_record);
  return 0;
}
