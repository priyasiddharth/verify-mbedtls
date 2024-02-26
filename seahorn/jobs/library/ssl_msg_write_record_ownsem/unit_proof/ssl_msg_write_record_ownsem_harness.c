#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

DEFINE_UNIT_PROOF(mbedtls_ssl_write_record) {
  sea_tracking_on();

  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  SEA_MKOWN(ssl);
   struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl->conf = &conf;
  // assert(sea_is_dereferenceable(ssl.conf, 1));
  mbedtls_ssl_handshake_params handshake;                                      \
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));                  \
  ssl->handshake = &handshake;

  // init_incoming_buf(&ssl);
  init_outgoing_buf(ssl);
  // assert(sea_is_dereferenceable(ssl.conf, 1));

  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  ssl->transform_out = &transform;
  // setup incoming & outgoing data
  // assert(sea_is_dereferenceable(ssl.conf, 1));  
  int force_flush = nd_int();
  assume(force_flush == 0 || force_flush == 1);
  size_t padlen = transform.ivlen - (ssl->out_msglen + 1) % transform.ivlen;
  assume(transform.ivlen <= MAX_PAD_LEN);
  // TODO: remove assume
  
  assume(ssl->out_msglen + 1 + transform.maclen + padlen < ssl->out_buf_len - (ssl->out_msg - ssl->out_buf));
  sea_printf("transform.ivlen:%d", transform.ivlen);
  sea_printf("padlen:%d transform.maclen:%d\n",
             padlen, transform.maclen);
  // sassert(sea_is_dereferenceable(ssl.out_buf, 1));
  // NOTE: call the SUT
  mbedtls_ssl_context *bor_ssl;
  SEA_BORROW(bor_ssl, ssl);
  int rc = mbedtls_ssl_write_record(bor_ssl, force_flush);
  // NOTE: Postcondition check
  if (rc == 0) {
    uint64_t taint;
    // SEA_READ_CACHE(taint, ssl->out_buf); 
    SEA_READ_CACHE(taint, ssl->out_buf); 
    if (force_flush) sassert(taint == 8);
  }
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_record);
  return 0;
}
