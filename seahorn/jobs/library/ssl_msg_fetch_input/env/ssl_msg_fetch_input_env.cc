extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

static size_t nb_bytes;

constexpr auto invoke_fn_mbedtls_ssl_recv_t = [](void *ctx, unsigned char *buf,
                                                 size_t len) {
  if (buf != NULL) {
    sassert(sea_is_dereferenceable(buf, len));
  }
  int ret = nd_int();
  assume(ret <= 0 || ret >= (int)nb_bytes);
  return ret;
};

constexpr auto invoke_fn_mbedtls_ssl_recv_timeout_t =
    [](void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
      if (buf != NULL) {
        sassert(sea_is_dereferenceable(buf, len));
      }
      int ret = nd_int();
      assume(ret <= 0 || ret >= (int)nb_bytes);
      return ret;
    };

extern "C" {
void set_min_recv_bytes(size_t num_bytes) { nb_bytes = num_bytes; }

constexpr auto expectations_mbedtls_ssl_recv_t =
    seamock::ExpectationBuilder()
        .times(seamock::Lt<2>())
        .invokeFn(invoke_fn_mbedtls_ssl_recv_t)
        .build();

constexpr auto expectations_mbedtls_ssl_recv_timeout_t =
    MakeExpectation(Expect(InvokeFn, invoke_fn_mbedtls_ssl_recv_timeout_t) ^
                    AND ^ Expect(Times, seamock::Lt<2>()));

MOCK_FUNCTION(ssl_recv_fn, expectations_mbedtls_ssl_recv_t, int,
              (void * /* ctx */, unsigned char * /* buf */, size_t /* len */))

MOCK_FUNCTION(ssl_recv_fn_timeout, expectations_mbedtls_ssl_recv_timeout_t, int,
              (void * /* ctx */, unsigned char * /* buf */, size_t /* len */,
               uint32_t /* timeout */))

// TODO: add buffer check for recv_fns
// TODO: add called atleast once for recv_fns
LAZY_MOCK_FUNCTION(ssl_get_timer, int, (void *))
LAZY_MOCK_FUNCTION(mbedtls_ssl_resend_hello_request, int,
                   (mbedtls_ssl_context *));
LAZY_MOCK_FUNCTION(mbedtls_ssl_set_timer, void,
                   (mbedtls_ssl_context *, uint32_t))
// LAZY_MOCK_FUNCTION(ssl_recv_fn, int, (void *, unsigned char *, size_t));
// LAZY_MOCK_FUNCTION(ssl_recv_fn_timeout, int,
//                    (void *, unsigned char *, size_t, uint32_t))
LAZY_MOCK_FUNCTION(mbedtls_ssl_flight_transmit, int, (mbedtls_ssl_context *))
SETUP_POST_CHECKS((ssl_recv_fn, ssl_recv_fn_timeout))
}
