#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <seamock_unit_proof.h>

#include <stddef.h>

#define NUM_OUT_BUFS NUM_OUT_RECORDS

extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
extern int ssl_recv_fn(void *ctx, unsigned char *buf, size_t len);
extern int ssl_get_timer(void *ctx);
extern void set_min_recv_bytes(size_t num_bytes);
extern int update_checksum(mbedtls_ssl_context *, const unsigned char *,
                           size_t);

mbedtls_ssl_context* make_ctx(void);

static size_t get_sequence_number(mbedtls_ssl_context* ssl) {
  size_t counter = 0;
  size_t shift = 0;
  for (size_t i = 8; i > mbedtls_ssl_ep_len(ssl); i--) {
    counter = ((size_t)ssl->cur_out_ctr[i - 1] << shift) | counter;
    shift+=8;
  }
  return counter;
}

typedef struct Buffer {
  unsigned char* out_buf;
  size_t out_buf_len;
  unsigned char* out_msg;
  size_t out_msg_len;
} BUFFER;

typedef struct Result {
  mbedtls_ssl_context *ssl;
  unsigned char *buf;
  int rc;
  bool append_flight;
  unsigned char hs_type;
} RESULT;

DEFINE_UNIT_PROOF(mbedtls_ssl_write_handshake_msg_ext) {
  sea_tracking_on();
  // NOTE: setup the precondition
  RESULT results[NUM_SSL_CTX];
  for(int k=0; k < NUM_SSL_CTX; k++) {
    struct mbedtls_ssl_context *ssl = make_ctx();
    size_t out_buf_size = GLOBAL_BUF_MAX_SIZE;
    BUFFER bufs[NUM_OUT_BUFS];
    for(int i=0; i < NUM_OUT_BUFS; i++) {
      bufs[i].out_buf = (unsigned char *)malloc(out_buf_size);
      memhavoc(bufs[i].out_buf, out_buf_size);
      ND_ALIGNED64_SIZE_T(out_msg_len);
      // NOTE: Invariant: msg should be > 0 bytes.
      // NOTE: We need to keep a padding of 8 bytes because business logic
      // NOTE: can increment out_msglen
      assume(out_msg_len > 10 && out_msg_len <= (out_buf_size - 8));
      size_t out_msg_len_start_offset = out_buf_size - 8 - out_msg_len;
      bufs[i].out_msg = bufs[i].out_buf + out_msg_len_start_offset;
      bufs[i].out_buf_len = out_buf_size;
      bufs[i].out_msg_len = out_msg_len;
    }
    int checksum = nd_int();
    int force_flush = nd_int();
    size_t idx = nd_size_t();
    assume(idx < NUM_OUT_BUFS);
    ssl->out_buf = bufs[idx].out_buf;
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) ssl, bufs[idx].out_buf_len);
    ssl->out_len = (unsigned char *)&bufs[idx].out_buf_len; // should fit in two bytes
    ssl->out_buf_len = bufs[idx].out_buf_len;
    ssl->out_msg = bufs[idx].out_msg;
    ssl->out_msglen = bufs[idx].out_msg_len;
    const unsigned char hs_type = ssl->out_msg[0];

    // NOTE: call the SUT
    int rc = mbedtls_ssl_write_handshake_msg_ext(ssl, checksum, 1);
    // NOTE: Postcondition check
    bool append_flight = ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM && 
        !(ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
            hs_type   == MBEDTLS_SSL_HS_HELLO_REQUEST);
    
    results[k] = (RESULT){.ssl = ssl, .buf = ssl->out_buf, .rc = rc, .append_flight = append_flight, .hs_type = hs_type};
    // if (rc == 0 && !append_flight) {
    //   size_t counter = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl);
    //   sassert(counter == seq_number + 1 + idx_count);
    // }        
    // if (rc == 0 && append_flight) {
    //   size_t cpysrc =  sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl);
    //   sassert(cpysrc == (size_t) bufs[idx].out_msg);
    // }
  }
//   size_t m = nd_size_t();
//   size_t n = nd_size_t();

//   assume (m != n);
//   assume(m < NUM_SSL_CTX);
//   assume(n < NUM_SSL_CTX);

// /*   if (rc == 0 && !append_flight) {
//     size_t counter = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)ssl);
//     sassert(counter == seq_number + 1 + idx_count);
//   }      */   
//   if (results[m].rc == 0 &&  results[m].append_flight && results[n].rc == 0 && results[n].append_flight) {
//     size_t cpysrc =  sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)results[m].ssl);
//     sassert(cpysrc != (size_t) results[n].buf);
//   }

  size_t p = nd_size_t();
  assume(p < NUM_SSL_CTX);

  if(results[p].hs_type != MBEDTLS_SSL_HS_HELLO_REQUEST && results[p].rc != MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
    sassert(sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *) results[p].ssl) > 10);
    //sassert(results[p].ssl->out_msglen > 10);
  }

}

mbedtls_ssl_context* make_ctx(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context* ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
  memhavoc(ssl, sizeof(mbedtls_ssl_context));
  // SEA_MKOWN(ssl);
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
  CALL_UNIT_PROOF(mbedtls_ssl_write_handshake_msg_ext);
  return 0;
}
