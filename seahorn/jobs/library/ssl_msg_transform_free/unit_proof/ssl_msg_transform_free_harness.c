#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>
#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_transform_free) {
  // NOTE: setup the precondition
  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  // NOTE: call the SUT
  mbedtls_ssl_transform_free(nd_bool() ? &transform : NULL);
  // NOTE: Postcondition check in env
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_transform_free);
  return 0;
}
