#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_set_outbound_transform) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);

  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  // setup incoming & outgoing data
  init_incoming_buf(&ssl);
  init_outgoing_buf(&ssl);

  ND_ALIGNED64_SIZE_T(sentinel_idx);
  // LEN goes till 8, idx goes till 7
  assume(sentinel_idx < MBEDTLS_SSL_SEQUENCE_NUMBER_LEN);
  // NOTE: call the SUT
  mbedtls_ssl_set_outbound_transform(&ssl, &transform);
  // NOTE: Postcondition check
  sassert(ssl.transform_out == &transform);
  sassert(ssl.cur_out_ctr[sentinel_idx] == 0);
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_set_outbound_transform);
  return 0;
}
