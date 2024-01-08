extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

#define INLINE __attribute__((always_inline))

constexpr auto invoke_mbedtls_ssl_msg_buffering_free_fn =
    [](mbedtls_ssl_context *ssl) {
      // TODO: add is_alloc check
    };

constexpr auto invoke_mbedtls_ssl_flight_free_fn =
    [](mbedtls_ssl_flight_item *flight) {
      sassert(sea_is_alloc((char *)flight));
    };

extern "C" {

constexpr auto expectations_mbedtls_ssl_msg_buffering_free =
    MakeExpectation(Expect(InvokeFn, invoke_mbedtls_ssl_msg_buffering_free_fn) ^
                    AND ^ Expect(Times, seamock::Eq<1>()));

constexpr auto expectations_mbedtls_ssl_flight_free =
    MakeExpectation(Expect(InvokeFn, invoke_mbedtls_ssl_flight_free_fn) ^ AND ^
                    Expect(Times, seamock::Eq<1>()));

MOCK_FUNCTION(mbedtls_ssl_msg_buffering_free,
              expectations_mbedtls_ssl_msg_buffering_free, void,
              (mbedtls_ssl_context *))
MOCK_FUNCTION(mbedtls_ssl_flight_free, expectations_mbedtls_ssl_flight_free,
              void, (mbedtls_ssl_flight_item *))
}
