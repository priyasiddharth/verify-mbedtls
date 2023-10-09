#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <ssl_misc.h>

int mbedtls_ssl_write_handshake_msg_ext(mbedtls_ssl_context *ssl,
                                        int update_checksum, int force_flush) {
  sassert(update_checksum == 1);
  sassert(force_flush == 1);
  sassert(sea_is_dereferenceable(ssl->out_msg,
                                 12)); // should be at-least 12 bytes long
  int r = nd_int();
  assume(r <= 0);
  return r;
}
