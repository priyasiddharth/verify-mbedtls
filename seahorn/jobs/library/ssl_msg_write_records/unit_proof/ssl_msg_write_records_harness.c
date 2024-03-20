#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

#define NUM_BUFS 3

mbedtls_ssl_context* make_ctx(void);

static size_t sequence_counters[NUM_BUFS];

static size_t get_sequence_number(mbedtls_ssl_context* ssl) {
  size_t counter = 0;
  size_t shift = 0;
  for (size_t i = 8; i > mbedtls_ssl_ep_len(ssl); i--) {
    counter = ((size_t)ssl->cur_out_ctr[i - 1] << shift) | counter;
    shift+=8;
  }
  return counter;
}

mbedtls_ssl_context* init2_outgoing_buf(mbedtls_ssl_context *ssl) {
  // setup outgoing data
  init_outgoing_buf(ssl);
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);
  ssl->transform_out = &transform;
  size_t padlen = transform.ivlen - (ssl->out_msglen + 1) % transform.ivlen;
  assume(transform.ivlen <= MAX_PAD_LEN);
  assume(padlen < ssl->out_buf_len);
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);

  assume(ssl->out_msglen + 1 + transform.maclen + padlen < ssl->out_buf_len - (ssl->out_msg - ssl->out_buf));
  unsigned char* data_start = ssl->out_msg;
  size_t data_len = ssl->out_msglen;
  unsigned char* out_buf = ssl->out_buf;
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf); 
  return ssl;
}

DEFINE_UNIT_PROOF(mbedtls_ssl_write_records) {
  sea_tracking_on();
  mbedtls_ssl_context *ssl = make_ctx();
  // assume(ssl->cur_out_ctr[mbedtls_ssl_ep_len(ssl)] <= 0xFE);
  // NOTE: call the SUT multiple times
  bool rc = true; 
  for(int i = 0;i < NUM_BUFS; i++) {
    int retcode = mbedtls_ssl_write_record(ssl, 1);
    rc = rc && (retcode == 0);
    size_t counter = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf));
    sea_printf("counter1(mid) value:%d\n", counter);
    sequence_counters[i] = counter;
    ssl = init2_outgoing_buf(ssl);
  }

  size_t idx1 = nd_size_t();
  size_t idx2 = nd_size_t();
 
  assume(idx1 < idx2);
  assume(idx2 < NUM_BUFS);
  // NOTE: Postcondition check
  if (rc) {
    sassert(sequence_counters[idx1] < sequence_counters[idx2]);
  } 
 /*  ssl = init2_outgoing_buf(ssl);
  sea_printf("counter1(mid) addr:%x]n", ssl->cur_out_ctr);
  sea_printf("counter1(mid) value:%d\n", get_sequence_number(ssl));
  int rc2 = mbedtls_ssl_write_record(ssl, 1); 
  // NOTE: Postcondition check
  if (rc1 == 0 && rc2 == 0) { 
    size_t count2 = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf)); 
    sea_printf("counter1:%d counter2:%d\n", count1, count2);
    sassert(count1 < count2);
  }  */
}

mbedtls_ssl_context* make_ctx(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl->conf = &conf;
  // assert(sea_is_dereferenceable(ssl.conf, 1));
  mbedtls_ssl_handshake_params handshake;                                      \
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));                  \
  ssl->handshake = &handshake;

  // setup transform
  // setup outgoing data
  return init2_outgoing_buf(ssl);
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_records);
  return 0;
}
