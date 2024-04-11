#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_mbedtls_util.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

#define NUM_BUFS NUM_OUT_RECORDS
#define NUM_CTX NUM_SSL_CTX

mbedtls_ssl_context* make_ctx(void);

static size_t sequence_counters[NUM_BUFS];


typedef struct out_buf_ptrs {
  unsigned char *out_buf;
  unsigned char *out_hdr;
  unsigned char *out_iv;
  unsigned char* out_msg;
  unsigned char *out_len;
  size_t out_msglen;
  size_t out_left;
  size_t out_buf_len; 
} OUT_BUF_SHAPE;

static size_t get_sequence_number(mbedtls_ssl_context* ssl) {
  size_t counter = 0;
  size_t shift = 0;
  for (size_t i = 8; i > mbedtls_ssl_ep_len(ssl); i--) {
    counter = ((size_t)ssl->cur_out_ctr[i - 1] << shift) | counter;
    shift+=8;
  }
  return counter;
}


void update_ssl_outgoing(mbedtls_ssl_context *ssl, OUT_BUF_SHAPE *s) {
  ssl->out_buf = s->out_buf;
  ssl->out_hdr = s->out_hdr;
  ssl->out_iv = s->out_iv;
  ssl->out_msg = s->out_msg;
  ssl->out_len = s->out_len;
  ssl->out_msglen = s->out_msglen;
  ssl->out_left = s->out_left;
  ssl->out_buf_len = s->out_buf_len;  
}

void update_outgoing_shape(OUT_BUF_SHAPE *s, mbedtls_ssl_context *ssl, size_t order) {
  s->out_buf = ssl->out_buf;
  s->out_hdr = ssl->out_hdr;
  s->out_iv = ssl->out_iv;
  s->out_msg = ssl->out_msg;
  s->out_len = ssl->out_len;
  s->out_msglen = ssl->out_msglen;
  s->out_left = ssl->out_left;
  s->out_buf_len = ssl->out_buf_len;  
}

mbedtls_ssl_context* init3_outgoing_buf(mbedtls_ssl_context *ssl, OUT_BUF_SHAPE *s) {
  // setup outgoing data
  update_ssl_outgoing(ssl, s);
  
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


DEFINE_UNIT_PROOF(mbedtls_ssl_write_records_ownsem) {
  sea_tracking_on();
  // mbedtls_ssl_context *ctxs[NUM_CTX];
  // OUT_BUF_SHAPE out_bufs[NUM_BUFS];
  // for(size_t i = 0; i < NUM_CTX; i++) {
  //   ctxs[i] = make_ctx();
  // }
  // size_t ctx_idx = nd_size_t();
  // assume(ctx_idx < NUM_CTX);
  mbedtls_ssl_context *ssl = make_ctx();
  assume(ssl->cur_out_ctr[mbedtls_ssl_ep_len(ssl)] <= (0xFF - NUM_BUFS - 2));
  // assume(ssl->cur_out_ctr[7] > 0) ;

  sassert(NUM_BUFS + 2 <= 0xFF00000000000000);
  // NOTE: call the SUT multiple times  
  size_t idx1 = nd_size_t();
  size_t idx2 = nd_size_t();
  size_t counter1, counter2;
  int rc1, rc2;
  SEA_WRITE_CACHE(ssl, get_sequence_number(ssl));
  unsigned char *own_bufs[NUM_BUFS];
  for(size_t i=0; i < NUM_BUFS; i++) {
    own_bufs[i] = nd_bool() ? (unsigned char*)malloc(4096) : (unsigned char*)malloc(2048);
    SEA_MKOWN_FAST(own_bufs[i]);
    size_t seq_counter;
    SEA_READ_CACHE(seq_counter, ssl);
    sea_printf("counter(pre) value:%ld\n", seq_counter);
    SEA_BORROW_FAST(ssl->out_buf, own_bufs[i]);
    SEA_WRITE_CACHE(ssl->out_buf, seq_counter);
    mbedtls_ssl_context *bor_ssl;
    SEA_BORROW_FAST(bor_ssl, ssl);
    int rc = mbedtls_ssl_write_record(bor_ssl, 1);
    assume(rc == 0);
    size_t counter;
    SEA_READ_CACHE(counter, own_bufs[i]);
    /* if (idx1 == i) {
      rc1 = rc;
      //counter1 = ; 
    } else if (idx2 == i) {
      rc2 = rc;
      //counter2 = counter;
    } */

  /*  counters[i] = counter1;
    rcs[i] = rc1;
    size_t *counter_ptr  = counters + i;
    int *rc_ptr = rcs + i;
    SEA_WRITE_CACHE(counter_ptr, counter1);
    SEA_WRITE_CACHE(rc_ptr, rc1); */
    //size_t seq_num = get_sequence_number(ssl);
    sea_printf("counter(mid) value:%ld\n", counter);
    sea_printf("rc:%d\n", rc);
  } 
  assume(idx1 < idx2);
  assume(idx2 < NUM_BUFS);
/*   SEA_READ_CACHE(counter1, counters + idx1);
  SEA_READ_CACHE(counter2, counters + idx2);
  SEA_READ_CACHE(rc1, rcs + idx1);
  SEA_READ_CACHE(rc2, rcs + idx2); */
  SEA_READ_CACHE(counter1, own_bufs[idx1]);
  SEA_READ_CACHE(counter2, own_bufs[idx2]);
  sassert(counter2 > counter1);

  // NOTE: Postcondition check
/*   if ((rc1 == 0) && (rc2 == 0)) {
    SEA_READ_CACHE(counter1, own_bufs[idx1]);
    SEA_READ_CACHE(counter2, own_bufs[idx2]);
    sassert(counter2 > counter1);
  } */
}


// DEFINE_UNIT_PROOF(mbedtls_ssl_write_records_ownsem) {
//   sea_tracking_on();
//   mbedtls_ssl_context *ctxs[NUM_CTX];
//   OUT_BUF_SHAPE out_bufs[NUM_BUFS];
//   for(size_t i = 0; i < NUM_CTX; i++) {
//     ctxs[i] = make_ctx();
//   }
//   size_t ctx_idx = nd_size_t();
//   assume(ctx_idx < NUM_CTX);
//   mbedtls_ssl_context *ssl = ctxs[ctx_idx];
//   assume(ssl->cur_out_ctr[mbedtls_ssl_ep_len(ssl)] <= (0xFF - NUM_BUFS - 2));
//   // assume(ssl->cur_out_ctr[7] > 0) ;

//   sassert(NUM_BUFS + 2 <= 0xFF00000000000000);
//   // assume(ssl->cur_out_ctr[mbedtls_ssl_ep_len(ssl)] <= 0xFE);
//   // NOTE: call the SUT multiple times
//   for(int i = 0;i < NUM_BUFS; i++) {
//     init_outgoing_buf(ssl);
//     update_outgoing_shape(&out_bufs[i], ssl, i);
//   }

//   size_t idx1 = nd_size_t();
//   size_t idx2 = nd_size_t();
 
//   assume(idx1 < idx2);
//   assume(idx2 < NUM_BUFS);

//   init3_outgoing_buf(ssl, &out_bufs[idx1]);

//   mbedtls_ssl_context *bor_ssl;
//   SEA_WRITE_CACHE(ssl, get_sequence_number(ssl));
//   SEA_BORROW(bor_ssl, ssl);
//   int rc1 = mbedtls_ssl_write_record(bor_ssl, 1);
//   size_t counter1;    
//   SEA_READ_CACHE(counter1, ssl);
//   //size_t seq_num = get_sequence_number(ssl);
//   sea_printf("counter1(mid) value:%ld\n", counter1);
//   //sea_printf("seq1(mid) value:%ld\n", seq_num);

//   init3_outgoing_buf(ssl, &out_bufs[idx2]);

//   //SEA_WRITE_CACHE(ssl, 0);
//   mbedtls_ssl_context *bor_ssl2;
//   SEA_BORROW(bor_ssl2, ssl);
//   int rc2 = mbedtls_ssl_write_record(bor_ssl2, 1);
//   size_t counter2;    
//   SEA_READ_CACHE(counter2, ssl);
//   sea_printf("counter2(mid) value:%d\n", counter2);
//   sassert(counter2 >= counter1);

//   // NOTE: Postcondition check
//   //if ((rc1 == 0) && (rc2 == 0)) {
//   // sassert(counter2 > counter1);
//   //}
// }


/* DEFINE_UNIT_PROOF(mbedtls_ssl_write_records_ownsem) {
  sea_tracking_on();
  mbedtls_ssl_context *ssl = make_ctx();
  // assume(ssl->cur_out_ctr[mbedtls_ssl_ep_len(ssl)] <= 0xFE);
  // NOTE: call the SUT multiple times
  bool rc = true; 
  for(int i = 0;i < NUM_BUFS; i++) {
    mbedtls_ssl_context *bor_ssl;
    SEA_BORROW(bor_ssl, ssl);
    int retcode = mbedtls_ssl_write_record(bor_ssl, 1);
    rc = rc && (retcode == 0);
    size_t counter;    
    SEA_READ_CACHE(counter, ssl->out_buf);
    sea_printf("counter(mid) value:%d\n", counter);
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
} 
 */
mbedtls_ssl_context* make_ctx(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  SEA_MKOWN_FAST(ssl);
  struct mbedtls_ssl_config conf;                                              \
  memhavoc(&conf, sizeof(mbedtls_ssl_config));                                 \
  ssl->conf = &conf;
  mbedtls_ssl_handshake_params handshake;                                      \
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));                  \
  ssl->handshake = &handshake;
  return ssl;
}

int main(void) {
  CALL_UNIT_PROOF(mbedtls_ssl_write_records_ownsem);
  return 0;
}
