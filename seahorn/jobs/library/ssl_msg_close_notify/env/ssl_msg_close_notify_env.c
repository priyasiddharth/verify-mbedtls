#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>

int mbedtls_ssl_write_record(mbedtls_ssl_context *ssl, int force_flush) {
  sassert(ssl->out_msgtype == MBEDTLS_SSL_MSG_ALERT);
  sassert(ssl->out_msglen == 2);
  sassert(ssl->out_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING);
  sassert(ssl->out_msg[1] == MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY);
  return nd_int();
}

int mbedtls_ssl_flush_output(mbedtls_ssl_context *ssl) { return nd_int(); }
