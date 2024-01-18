#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_ssl_flush_output = [](mbedtls_ssl_context *ssl) {
  if (ssl->out_left > 0) {
    unsigned char *buf = ssl->out_hdr - ssl->out_left;
    sassert(sea_is_dereferenceable(buf, ssl->out_left));
  }
  int ret_val = nd_int();
  return ret_val; // You may need to constrain the return value as necessary
};

constexpr auto invoke_ssl_write_record = [](mbedtls_ssl_context *ssl,
                                            int force) {
  int ret_val = nd_int();
  return ret_val; // You may need to constrain the return value as necessary
};

// Mock for mbedtls_ssl_write_record
constexpr auto invoke_mbedtls_ssl_write_record =
    [](mbedtls_ssl_context *ssl, int force_flush) { return nd_int(); };

extern "C" {

constexpr auto expectations_flush_output =
    seamock::ExpectationBuilder().invokeFn(invoke_ssl_flush_output).build();
MOCK_FUNCTION(mbedtls_ssl_flush_output, expectations_flush_output, int,
              (mbedtls_ssl_context *));

constexpr auto expectations_write_record =
    seamock::ExpectationBuilder().invokeFn(invoke_ssl_write_record).build();
MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_write_record, int,
              (mbedtls_ssl_context *, int));
}
