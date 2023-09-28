#ifndef SEAHORN_MBEDTLS_UTIL_H_
#define SEAHORN_MBEDTLS_UTIL_H_

#include "mbedtls/ssl.h"

#define HAVOC_SSL_CTX(ssl)                                                     \
  struct mbedtls_ssl_context ssl;                                              \
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));

#define HAVOC_ADD_CONF_TO_SSL_CTX(ssl)                                         \
  struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl.conf = &conf;

#define ADD_CONF_TO_SSL_CTX(ssl)                                               \
  struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl.conf = &conf;

void init_outgoing_buf(struct mbedtls_ssl_context *);
void init_incoming_buf(struct mbedtls_ssl_context *);
bool outgoing_buf_valid(struct mbedtls_ssl_context *);
bool incoming_buf_valid(struct mbedtls_ssl_context *);

#endif // SEAHORN_MBEDTLS_UTIL_H_
