#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

extern "C" {

constexpr auto invoke_fn_mbedtls_ssl_send_t =
    [](void *ctx, const unsigned char *buf, size_t len) {
      sassert(sea_is_dereferenceable(buf, len));
      return nd_int();
    };

constexpr auto expectations_mbedtls_ssl_send_t =
    MakeExpectation(Expect(InvokeFn, invoke_fn_mbedtls_ssl_send_t));
MOCK_FUNCTION(send_fn, expectations_mbedtls_ssl_send_t, int,
              (void * /* ctx */, const unsigned char * /* buf */,
               size_t /* len */))
}
