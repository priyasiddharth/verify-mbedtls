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

constexpr auto invoke_calloc = [](size_t number, size_t size) {
  sassert(size <= GLOBAL_BUF_MAX_SIZE);
  void *ptr = malloc(size);
  memhavoc(ptr, size);
  memset(ptr, number, size);
  return ptr;
};

extern "C" {

constexpr auto expectations_mbedtls_ssl_write_record =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_fn_mbedtls_ssl_write_record)
        .times(seamock::Lt<2>())
        .build();
MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_mbedtls_ssl_write_record,
              int, (mbedtls_ssl_context *, int))

constexpr auto expectations_calloc =
    seamock::ExpectationBuilder().invokeFn(invoke_calloc).build();
MOCK_FUNCTION(calloc, expectations_calloc, void *, (size_t, size_t))

LAZY_MOCK_FUNCTION(update_checksum, int,
                   (mbedtls_ssl_context *, const unsigned char *, size_t))
ERR_SUC_MOCK_FUNCTION(ssl_flight_append, (mbedtls_ssl_context *))

SETUP_POST_CHECKS((mbedtls_ssl_write_record))
}
