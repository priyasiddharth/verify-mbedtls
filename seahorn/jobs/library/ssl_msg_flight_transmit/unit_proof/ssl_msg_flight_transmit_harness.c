#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_flight_transmit(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
void test_mbedtls_ssl_flight_transmit(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  // setup transform
  mbedtls_ssl_transform transform;
  memhavoc(&transform, sizeof(mbedtls_ssl_transform));
  ssl.transform_out = &transform;
  // setup handshake
  mbedtls_ssl_handshake_params handshake;
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));
  ssl.handshake = &handshake;
  mbedtls_ssl_transform alt_transform;
  memhavoc(&alt_transform, sizeof(mbedtls_ssl_transform));
  ssl.handshake->alt_transform_out = &alt_transform;
  // setup flight_item
  struct mbedtls_ssl_flight_item flight;
  memhavoc(&flight, sizeof(mbedtls_ssl_flight_item));
  flight.next = NULL;
  unsigned char *msg = (unsigned char *)malloc(GLOBAL_BUF_MAX_SIZE);
  flight.p = msg;
  flight.len = nd_size_t();
  ssl.handshake->flight = &flight;
  struct mbedtls_ssl_flight_item cur_flight;
  memhavoc(&cur_flight, sizeof(mbedtls_ssl_flight_item));
  cur_flight.next = NULL;
  unsigned char *cur_msg = (unsigned char *)malloc(GLOBAL_BUF_MAX_SIZE);
  cur_flight.p = cur_msg;
  cur_flight.len = nd_size_t();
  handshake.cur_msg = &cur_flight;
  // TODO: add nd on cur_msg_p
  handshake.cur_msg_p = cur_msg;
  size_t out_buf_size = GLOBAL_BUF_MAX_SIZE;
  unsigned char *out_buf = (unsigned char *)malloc(out_buf_size);
  memhavoc(out_buf, out_buf_size);
  ssl.out_buf = out_buf;
  ssl.out_len = (unsigned char *)&out_buf_size; // should fit in two bytes //
  size_t out_msg_len = nd_size_t();
  // NOTE: Invariant: msg should be > 0 bytes.
  // NOTE: We need to keep a padding of 12 bytes because business logic
  // NOTE: can increment out_msglen
  assume(out_msg_len > 12 && out_msg_len <= (out_buf_size - 12));
  size_t out_msg_len_start_offset = out_buf_size - 12 - out_msg_len;
  ssl.out_msg = ssl.out_buf + out_msg_len_start_offset;
  ssl.out_msglen = out_msg_len;
  assume(cur_flight.len < ssl.out_msglen);
  assume(flight.len < ssl.out_msglen);
  assume(ssl.handshake->cur_msg_p >=
         ssl.handshake->cur_msg->p + ssl.handshake->cur_msg->len);

  // NOTE: call the SUT
  int rc = mbedtls_ssl_flight_transmit(&ssl);
  // NOTE: Postcondition check in environment
}

int main(void) {
  test_mbedtls_ssl_flight_transmit();
  return 0;
}
