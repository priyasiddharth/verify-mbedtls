#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_write_handshake_msg_ext(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
extern int ssl_recv_fn(void *ctx, unsigned char *buf, size_t len);
extern int ssl_get_timer(void *ctx);
extern void set_min_recv_bytes(size_t num_bytes);
extern int update_checksum(mbedtls_ssl_context *, const unsigned char *,
                           size_t);
void test_mbedtls_ssl_write_handshake_msg_ext(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_context ssl;
  memhavoc(&ssl, sizeof(mbedtls_ssl_context));
  struct mbedtls_ssl_config conf;
  memhavoc(&conf, sizeof(mbedtls_ssl_config));
  ssl.conf = &conf;
  mbedtls_ssl_handshake_params handshake;
  memhavoc(&handshake, sizeof(mbedtls_ssl_handshake_params));
  ssl.handshake = &handshake;
  handshake.update_checksum = &update_checksum;
  struct mbedtls_ssl_flight_item flight;
  memhavoc(&flight, sizeof(mbedtls_ssl_flight_item));
  flight.next = NULL;
  ssl.handshake->flight = &flight;
  size_t out_buf_size = GLOBAL_BUF_MAX_SIZE;
  unsigned char *out_buf = (unsigned char *)malloc(out_buf_size);
  memhavoc(out_buf, out_buf_size);
  ssl.out_buf = out_buf;
  ssl.out_len = (unsigned char *)&out_buf_size; // should fit in two bytes
  size_t out_msg_len = nd_size_t();
  // NOTE: Invariant: msg should be > 0 bytes.
  // NOTE: We need to keep a padding of 8 bytes because business logic
  // NOTE: can increment out_msglen
  assume(out_msg_len > 10 && out_msg_len <= (out_buf_size - 8));
  size_t out_msg_len_start_offset = out_buf_size - 8 - out_msg_len;
  ssl.out_msg = ssl.out_buf + out_msg_len_start_offset;
  ssl.out_msglen = out_msg_len;
  int checksum = nd_int();
  int force_flush = nd_int();
  // NOTE: call the SUT
  int rc = mbedtls_ssl_write_handshake_msg_ext(&ssl, checksum, force_flush);
  // NOTE: Postcondition check in environment
}

int main(void) {
  test_mbedtls_ssl_write_handshake_msg_ext();
  return 0;
}
