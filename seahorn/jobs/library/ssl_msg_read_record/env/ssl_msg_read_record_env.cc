extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

#define INLINE __attribute__((always_inline))

constexpr auto invoke_zero_and_free = [](void *buf, size_t len) {
  // TODO: add is_alloc check
  sassert(sea_is_dereferenceable(buf, len));
};

static int last_read_record_retval = -1;
constexpr auto invoke_ssl_read_record = [](mbedtls_ssl_context *ssl,
                                           unsigned update_hs_digest) {
  int ret_val = nd_int();
  last_read_record_retval = ret_val;
  return 0;
};

extern "C" {
int get_last_read_record_retval(void) { return last_read_record_retval; }

// to exit do-while loop after 1 iter
SUC_MOCK_FUNCTION(ssl_consume_current_message, (mbedtls_ssl_context *))
SUC_MOCK_FUNCTION(ssl_get_next_record, (mbedtls_ssl_context *))
SUC_MOCK_FUNCTION(ssl_buffer_message, (mbedtls_ssl_context *))
SUC_MOCK_FUNCTION(mbedtls_ssl_handle_message_type, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(
    mbedtls_ssl_update_handshake_status,
    ERR_SUC_MOCK_FUNCTION(ssl_load_buffered_message,
                          (mbedtls_ssl_context *))(mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_check_timer, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_fetch_input, (mbedtls_ssl_context *, size_t))
ERR_SUC_MOCK_FUNCTION(ssl_handle_possible_reconnect, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flush_output, (mbedtls_ssl_context *))
}
