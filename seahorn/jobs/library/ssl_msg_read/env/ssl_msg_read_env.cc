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

constexpr auto invoke_ssl_read_record = [](mbedtls_ssl_context *ssl,
                                           unsigned update_hs_digest) {
  int ret_val = nd_int();
  return 0;
};

extern "C" {
ERR_SUC_MOCK_FUNCTION(mbedtls_md_hmac_reset, (mbedtls_md_context_t *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flush_output, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flight_transmit, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_handshake, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_resend_hello_request, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_timer, (void *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_renegotiate, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_start_renegotiation, (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_get_record_expansion,
                      (const mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_write_record,
                      (const mbedtls_ssl_context *, int))

constexpr auto expectations_zero_and_free =
    MakeExpectation(Expect(InvokeFn, invoke_zero_and_free));
MOCK_FUNCTION(mbedtls_zeroize_and_free, expectations_zero_and_free, void,
              (void *, size_t))
constexpr auto expectatations_mbedtls_ssl_read_record =
    MakeExpectation(Expect(InvokeFn, invoke_ssl_read_record));
MOCK_FUNCTION(mbedtls_ssl_read_record, expectatations_mbedtls_ssl_read_record,
              int, (mbedtls_ssl_context *, unsigned));
}
