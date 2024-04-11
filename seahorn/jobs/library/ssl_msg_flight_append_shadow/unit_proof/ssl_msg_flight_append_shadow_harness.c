#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

#define NUM_OUT_BUFS NUM_OUT_RECORDS
#define NUM_FLIGHT_APPEND NUM_FLIGHT_APPEND_OPS
extern MBEDTLS_CHECK_RETURN_CRITICAL int ssl_flight_append(mbedtls_ssl_context *ssl);

mbedtls_ssl_context* make_ctx(void);

typedef struct BUF {
    unsigned char* buf;
    int rc;
} Buf;

DEFINE_UNIT_PROOF(mbedtls_ssl_flight_append_shadow) {
  sea_tracking_on();
  mbedtls_ssl_context *ssl = make_ctx();
  size_t own_buf_len = 4096;
  size_t success_count = 0;
  Buf out_bufs[NUM_FLIGHT_APPEND];
  sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) ssl, 0);
  unsigned char* cand_bufs[NUM_OUT_BUFS];
  for(int i=0; i < NUM_FLIGHT_APPEND; i++) {
     for (int j=0; j < NUM_OUT_BUFS;j++) {
      cand_bufs[j] = (unsigned char *) malloc(own_buf_len);    
    }
    size_t cand_idx = nd_size_t();
    assume(cand_idx < NUM_OUT_BUFS);
    unsigned char *own_buf = cand_bufs[cand_idx];   
    memhavoc(own_buf, own_buf_len);   
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) own_buf, 0);
    size_t out_msg_cpy_cnt = nd_size_t();
    ssl->out_buf = own_buf;
    ssl->out_msg = ssl->out_buf;
    ssl->out_buf_len = own_buf_len;
    ssl->out_msglen = ssl->out_buf_len;

    // NOTE: Call the SUT
    int rc = ssl_flight_append(ssl);
    //assume(rc == 0);
    out_bufs[i].buf = own_buf;
    out_bufs[i].rc = rc;
    //out_bufs[i].length = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl);
    // assume(rc == 0);
    if (rc == 0) {
      success_count = success_count + 1; 
      // sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl->out_buf);
    }/*  else {
    //  sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl) == 1);
    //} */
    sea_printf("Success count:%d\n", success_count);
  }
  // sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl) == success_count);
  size_t idx1 = nd_size_t();
  size_t idx2 = nd_size_t();
  assume(idx1 < idx2);
  assume(idx2 < NUM_FLIGHT_APPEND);
  if (out_bufs[idx1].rc == 0 && out_bufs[idx2].rc == 0) {
    sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)out_bufs[idx1].buf) <
        sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)out_bufs[idx2].buf));
  }
}

mbedtls_ssl_context* make_ctx(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;                                             
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 
  ssl->conf = &conf;
  mbedtls_ssl_handshake_params handshake;                                   
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));                 
  ssl->handshake = &handshake;
    // setup flight_item
  struct mbedtls_ssl_flight_item flight;
  memhavoc(&flight, sizeof(mbedtls_ssl_flight_item));
  flight.next = NULL;
  unsigned char *msg = (unsigned char *)malloc(GLOBAL_BUF_MAX_SIZE);
  flight.p = msg;
  flight.len = nd_size_t();
  ssl->handshake->flight = &flight;
  return ssl;
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_flight_append_shadow);
  return 0;
}