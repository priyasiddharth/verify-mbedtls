extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>


constexpr auto invoke_fn_mbedtls_ssl_write_record = [](mbedtls_ssl_context *ssl,
                                                       int force_flush) {
  size_t len = ssl->out_msglen;
  unsigned char *out_msg = ssl->out_msg;
  if (out_msg != NULL) {
    sassert(sea_is_dereferenceable(out_msg, len));
  }
  return nd_int();
};

extern "C" {
constexpr auto expectations_mbedtls_ssl_write_record =
    MakeExpectation(Expect(InvokeFn, invoke_fn_mbedtls_ssl_write_record) ^ AND ^
                    Expect(Times, 1_c));

MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_mbedtls_ssl_write_record,
              int, (mbedtls_ssl_context *, int))

LAZY_MOCK_FUNCTION(update_checksum, int, (mbedtls_ssl_context *, const unsigned char *, size_t))
}