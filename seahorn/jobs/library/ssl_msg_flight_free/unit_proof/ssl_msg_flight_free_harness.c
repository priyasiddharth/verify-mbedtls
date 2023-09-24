#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_config.h>
#include <seahorn_util.h>
#include <stddef.h>

void test_mbedtls_ssl_flight_free(void);
extern int ssl_recv_fn_timeout(void *ctx, unsigned char *buf, size_t len,
                               uint32_t timeout);
extern int ssl_recv_fn(void *ctx, unsigned char *buf, size_t len);
extern int ssl_get_timer(void *ctx);
extern void set_min_recv_bytes(size_t num_bytes);
extern int update_checksum(mbedtls_ssl_context *, const unsigned char *,
                           size_t);
void test_mbedtls_ssl_flight_free(void) {
  // NOTE: setup the precondition
  struct mbedtls_ssl_flight_item *flight =
      (struct mbedtls_ssl_flight_item *)malloc(
          sizeof(struct mbedtls_ssl_flight_item));
  memhavoc(flight, sizeof(mbedtls_ssl_flight_item));
  flight->next = NULL;
  unsigned char *msg = (unsigned char *)malloc(GLOBAL_BUF_MAX_SIZE);
  flight->p = msg;
  sea_tracking_on();
  // NOTE: call the SUT
  mbedtls_ssl_flight_free(flight);
  // NOTE: Postcondition check in environment
  sassert(!sea_is_alloc((char *)flight->p));
  sassert(!sea_is_alloc((char *)flight));
  sea_tracking_off();
}

int main(void) {
  test_mbedtls_ssl_flight_free();
  return 0;
}
