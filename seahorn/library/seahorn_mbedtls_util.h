#ifndef SEAHORN_MBEDTLS_UTIL_H_
#define SEAHORN_MBEDTLS_UTIL_H_

#include "mbedtls/ssl.h"

void init_outgoing_buf(struct mbedtls_ssl_context *);
void init_incoming_buf(struct mbedtls_ssl_context *);

#endif // SEAHORN_MBEDTLS_UTIL_H_
