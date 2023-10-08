#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(ssl_msg_start_handshake_msg) {
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

  assume(ssl.out_msglen >= 4);

  unsigned hs_type = nd_uint32_t();
  unsigned char *buf;
  size_t buf_len;
  // NOTE: call the SUT
  int rc = ssl_msg_start_handshake_msg(&ssl, hs_type, &buf, &buf_len);
  // NOTE: Postcondition check
  sassert(buf == ssl.out_msg + 4);
  sassert(buf_len == MBEDTLS_SSL_OUT_CONTENT_LEN - 4);
}

int main(void) {
  CALL_UNIT_PROOF(ssl_msg_start_handshake_msg);
  return 0;
}
