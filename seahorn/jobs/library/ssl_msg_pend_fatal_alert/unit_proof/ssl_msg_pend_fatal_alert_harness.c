#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_pend_fatal_alert) {
  // NOTE: setup the precondition
  HAVOC_SSL_CTX(ssl);
  // setup incoming data
  init_incoming_buf(&ssl);
  unsigned char alert_type = nd_uchar();
  int alert_reason = nd_int();
  // NOTE: call the SUT
  mbedtls_ssl_pend_fatal_alert(&ssl, alert_type, alert_reason);
  // NOTE: Postcondition check
  sassert(ssl.send_alert == 1);
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_pend_fatal_alert);
  return 0;
}
