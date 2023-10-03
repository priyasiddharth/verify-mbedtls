extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

#define INLINE __attribute__((always_inline))

constexpr auto invoke_mbedtls_ssl_buffering_free_fn =
    [](mbedtls_ssl_context *ssl) {
      // TODO: add is_alloc check
    };

constexpr auto invoke_mbedtls_ssl_flight_free_fn =
    [](mbedtls_ssl_flight_item *flight) {
      sassert(sea_is_alloc((char *)flight));
    };

extern "C" {

// to exit do-while loop after 1 iter
// SUC_MOCK_FUNCTION(ssl_consume_current_message, (mbedtls_ssl_context *))
// SUC_MOCK_FUNCTION(ssl_get_next_record, (mbedtls_ssl_context *))
// SUC_MOCK_FUNCTION(ssl_buffer_message, (mbedtls_ssl_context *))
// SUC_MOCK_FUNCTION(mbedtls_ssl_handle_message_type, (mbedtls_ssl_context *))
// ERR_SUC_MOCK_FUNCTION(
//     mbedtls_ssl_update_handshake_status,
//     ERR_SUC_MOCK_FUNCTION(ssl_load_buffered_message,
//                           (mbedtls_ssl_context *))(mbedtls_ssl_context *))
// ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_check_timer, (mbedtls_ssl_context *))
// ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_fetch_input, (mbedtls_ssl_context *,
// size_t)) ERR_SUC_MOCK_FUNCTION(ssl_handle_possible_reconnect,
// (mbedtls_ssl_context *)) ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flush_output,
// (mbedtls_ssl_context *))
constexpr auto expectations_mbedtls_ssl_buffering_free =
    MakeExpectation(Expect(InvokeFn, invoke_mbedtls_ssl_buffering_free_fn) ^
                    AND ^ Expect(Times, Eq(1_c)));

constexpr auto expectations_mbedtls_ssl_flight_free =
    MakeExpectation(Expect(InvokeFn, invoke_mbedtls_ssl_flight_free_fn) ^ AND ^
                    Expect(Times, Eq(1_c)));

MOCK_FUNCTION(mbedtls_ssl_buffering_free,
              expectations_mbedtls_ssl_buffering_free, void,
              (mbedtls_ssl_context *))
MOCK_FUNCTION(mbedtls_ssl_flight_free, expectations_mbedtls_ssl_flight_free,
              void, (mbedtls_ssl_flight_item *))
}
