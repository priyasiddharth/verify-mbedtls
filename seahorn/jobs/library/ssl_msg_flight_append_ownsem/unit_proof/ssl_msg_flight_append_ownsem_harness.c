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
    size_t cpy_count;
    int rc;
} Buf;

DEFINE_UNIT_PROOF(mbedtls_ssl_flight_append_ownsem) {
  sea_tracking_on();
  mbedtls_ssl_context *ssl = make_ctx();
  size_t own_buf_len = 4096;
  //sea_printf("Running with %d bufs:\n", NUM_OUT_BUFS);
  size_t success_count = 0;
  SEA_WRITE_CACHE(ssl, 0 /* init count */);
  Buf out_bufs[NUM_FLIGHT_APPEND];
  unsigned char* cand_bufs[NUM_OUT_BUFS];
  for(int i=0; i < NUM_FLIGHT_APPEND; i++) {
    for (int j=0; j < NUM_OUT_BUFS;j++) {
      cand_bufs[j] = (unsigned char *) malloc(own_buf_len);    
    }
    size_t cand_idx = nd_size_t();
    assume(cand_idx < NUM_OUT_BUFS);
    unsigned char *own_buf = cand_bufs[cand_idx];   
    memhavoc(own_buf, own_buf_len);   
    SEA_MKOWN(own_buf);
    size_t out_msg_cpy_cnt = nd_size_t();
    SEA_SET_FATPTR_SLOT1(own_buf, out_msg_cpy_cnt);
    //sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) own_buf, idx);
    SEA_WRITE_CACHE(own_buf, 0 /* init count */);
    SEA_BORROW(ssl->out_buf, own_buf);
    ssl->out_msg = ssl->out_buf;
    ssl->out_buf_len = own_buf_len;
    ssl->out_msglen = ssl->out_buf_len;
    // NOTE: Call the SUT
    mbedtls_ssl_context *bor_ssl;
    SEA_BORROW(bor_ssl, ssl); 
    size_t count;
    SEA_READ_CACHE(count, bor_ssl->out_buf);
    int rc = ssl_flight_append(bor_ssl);
    // sea_printf("retcode:%d\n", rc);
    SEA_DIE(own_buf);
    // assume(rc == 0);
    out_bufs[i].cpy_count = out_msg_cpy_cnt;
    size_t cached_rc;
    SEA_READ_CACHE(cached_rc, ssl);
    out_bufs[i].rc = (int) cached_rc;
    // if (rc == 0) {
    //   success_count++;  
    //   sassert(out_msg_cpy_cnt == i + 1);
    // }  
      // sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl->out_buf) == idx + 1);
    // } else {
    //   size_t allocFreed;
    //   SEA_READ_CACHE(allocFreed, ssl);
    //   sassert(allocFreed == 1);
    // // sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl) == 1);
    // }
  }
  //size_t node_count;
  //SEA_READ_CACHE(node_count, ssl);
  // sassert(node_count == success_count);

  size_t idx1 = nd_size_t();
  size_t idx2 = nd_size_t();
  assume(idx1 < idx2);
  assume(idx2 < NUM_FLIGHT_APPEND);
  //if (out_bufs[idx].rc == 0) {
  //  sassert(out_bufs[idx].cpy_count == idx + 1);
  //}  
  if (out_bufs[idx1].rc == 0 && out_bufs[idx2].rc == 0) {
    sassert(out_bufs[idx1].cpy_count < out_bufs[idx2].cpy_count);
  }
}



// DEFINE_UNIT_PROOF(mbedtls_ssl_flight_append_ownsem) {
//   sea_tracking_on();
//   mbedtls_ssl_context *ssl = make_ctx();
//   unsigned char* out_bufs[NUM_OUT_BUFS];
//   size_t own_buf_len = 4096;
//   for(int i=0; i < NUM_OUT_BUFS; i++) {
//     out_bufs[i] = (unsigned char *) malloc(own_buf_len);   
//     memhavoc(out_bufs[i], own_buf_len);   
//   }
//   size_t idx = nd_size_t();
//   assume(idx < NUM_OUT_BUFS);
//   unsigned char* own_buf = out_bufs[idx];
//   SEA_MKOWN(own_buf);
//   size_t out_msg_cpy_cnt = nd_size_t();
//   SEA_SET_FATPTR_SLOT1(own_buf, out_msg_cpy_cnt);
//   //sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) own_buf, idx);
//   SEA_WRITE_CACHE(own_buf, idx /* init count */);
//   SEA_BORROW(ssl->out_buf, own_buf);
//   SEA_WRITE_CACHE(ssl, 0);
//   ssl->out_msg = ssl->out_buf;
//   ssl->out_buf_len = own_buf_len;
//   ssl->out_msglen = ssl->out_buf_len;
//   // NOTE: Call the SUT
//   mbedtls_ssl_context *bor_ssl;
//   SEA_BORROW(bor_ssl, ssl); 
//   size_t count;
//   SEA_READ_CACHE(count, bor_ssl->out_buf);
//   sea_printf("src_count(0):%ld\n", count);
//   int rc = ssl_flight_append(bor_ssl);
//   SEA_DIE(own_buf);
//   if (rc == 0) {
//     size_t count;
//     sassert(out_msg_cpy_cnt == idx + 1);
//     // sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl->out_buf) == idx + 1);
//   } else {
//     size_t allocFreed;
//     SEA_READ_CACHE(allocFreed, ssl);
//     sassert(allocFreed == 1);
//     // sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl) == 1);
//   }
// }

mbedtls_ssl_context* make_ctx(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  SEA_MKOWN(ssl);
  struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl->conf = &conf;
  mbedtls_ssl_handshake_params handshake;                                      \
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));                  \
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
  CALL_UNIT_PROOF(mbedtls_ssl_flight_append_ownsem);
  return 0;
}
