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
  HAVOC_SSL_CTX(ssl);
  HAVOC_ADD_CONF_TO_SSL_CTX(ssl);
  HAVOC_ADD_HANDSHAKE_TO_SSL_CTX(ssl);
  // setup transform
  // setup outgoing data
  init_outgoing_buf(&ssl);
  sea_printf("ssl.out_buf:%x\n", ssl.out_buf);
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  sea_printf("ssl.out_buf:%x\n", ssl.out_buf);
  ssl.transform_out = &transform;
  int force_flush = nd_int();
  assume(force_flush == 0 || force_flush == 1);
  size_t padlen = transform.ivlen - (ssl.out_msglen + 1) % transform.ivlen;
  assume(transform.ivlen <= MAX_PAD_LEN);
  assume(padlen < ssl.out_buf_len);
  sea_printf("ssl.out_buf:%x\n", ssl.out_buf);

  // assume(transform.maclen < ssl.out_buf_len);
  assume(ssl.out_msglen + 1 + transform.maclen + padlen < ssl.out_buf_len - (ssl.out_msg - ssl.out_buf));
  unsigned char* data_start = ssl.out_msg;
  size_t data_len = ssl.out_msglen;
  unsigned char* out_buf = ssl.out_buf;
  sea_printf("ssl.out_buf:%x\n", ssl.out_buf);
  // NOTE: call the SUT
  int rc = mbedtls_ssl_write_record(&ssl, force_flush);
  // NOTE: Postcondition check
  if (rc == 0) { 
    size_t count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl.out_buf));
    if (force_flush) sassert(count == 8);
  }
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_record);
  return 0;
}
