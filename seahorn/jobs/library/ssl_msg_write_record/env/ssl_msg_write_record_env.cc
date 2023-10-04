extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

#define INLINE __attribute__((always_inline))

// constexpr auto invoke_zero_and_free = [](void *buf, size_t len) {
//   // TODO: add is_alloc check
//   sassert(sea_is_dereferenceable(buf, len));
// };

// static int last_read_record_retval = -1;
// constexpr auto invoke_ssl_read_record = [](mbedtls_ssl_context *ssl,
//                                            unsigned update_hs_digest) {
//   int ret_val = nd_int();
//   last_read_record_retval = ret_val;
//   return 0;
// };

extern "C" {
SUC_MOCK_FUNCTION(mbedtls_ssl_write_version,
                  (unsigned char *, int, mbedtls_ssl_protocol_version))
// SUC_MOCK_FUNCTION(mbedtls_ssl_update_out_pointers,
//                   (mbedtls_ssl_context *, mbedtls_transform_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_space_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_payload_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_flush_output, (mbedtls_ssl_context *))
// ERR_SUC_MOCK_FUNCTION(mbedtls_ssl_out_hdr_len, (mbedtls_ssl_context *))
}
