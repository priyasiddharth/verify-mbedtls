extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <ssl_misc.h>

#include <seahorn/seahorn.h>
#include <seahorn_util.h>
}
#include <seamock.hh>

extern "C" {
constexpr auto invoke_zeroize_and_free_fn = [](void *buf, size_t len) {
  sassert(sea_is_dereferenceable(buf, len));
};

constexpr auto invoke_parse_record_header_fn =
    [](mbedtls_ssl_context const *ssl, unsigned char *buf, size_t len,
       mbedtls_record *rec) {
      size_t idx = nd_size_t();
      assume(idx <= len);
      sassert(sea_is_dereferenceable(buf, idx));
      return nd_int();
    };

constexpr auto expectations_zeroize_and_free =
    MakeExpectation(Expect(InvokeFn, invoke_zeroize_and_free_fn));

constexpr auto expectations_parse_record_header =
    MakeExpectation(Expect(InvokeFn, invoke_parse_record_header_fn));

LAZY_MOCK_FUNCTION(mbedtls_ssl_decrypt_buf, int,
                   (mbedtls_ssl_context const *, mbedtls_ssl_transform *,
                    mbedtls_record *))

MOCK_FUNCTION(mbedtls_zeroize_and_free, expectations_zeroize_and_free, void,
              (void * /* buf */, size_t /* len */))

MOCK_FUNCTION(ssl_parse_record_header, expectations_parse_record_header, int,
              (mbedtls_ssl_context const *, unsigned char *, size_t,
               mbedtls_record *))
}
