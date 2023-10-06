#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

extern int ssl_get_timer(void *);

DEFINE_UNIT_PROOF(mbedtls_ssl_write) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup incoming & outgoing data
  init_incoming_buf(&ssl);
  init_outgoing_buf(&ssl);
  // set in msg type
  assume(ssl.in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE);
  // setup recv fn
  ssl.f_get_timer = &ssl_get_timer;
  // setup buffer
  ND_ALIGNED64_SIZE_T(buf_size);
  assume(buf_size < ssl.out_msglen);
  ND_ALIGNED64_SIZE_T(out_left);
  assume(out_left < ssl.out_msglen);

  size_t sentinel_idx = nd_size_t(); // byte aligned
  assume(sentinel_idx < ssl.out_msglen);
  unsigned char sentinel_val = ssl.out_msg[sentinel_idx];
  unsigned char *buf = (unsigned char *)malloc(buf_size);
  ND_ALIGNED64_SIZE_T(len);
  assume(len == buf_size);
  assume(sentinel_idx < len);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_write(&ssl, buf, len);
  // NOTE: Postcondition check
  sassert(outgoing_buf_valid(&ssl));
  if (rc > 0) {
    assume(sentinel_idx < (size_t)rc);
    sassert(ssl.out_msg[sentinel_idx] == sentinel_val);
  }
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write);
  return 0;
}
