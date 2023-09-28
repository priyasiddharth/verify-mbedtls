#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

extern void set_alert_msg_params(unsigned char, unsigned char);

DEFINE_UNIT_PROOF(mbedtls_ssl_send_alert_message) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  // setup outgoing data
  init_outgoing_buf(&ssl);
  unsigned char level = nd_uchar();
  unsigned char message = nd_uchar();
  // record data in env
  set_alert_msg_params(level, message);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_send_alert_message(&ssl, level, message);
  // NOTE: Postcondition check in environment
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_send_alert_message);
  return 0;
}
