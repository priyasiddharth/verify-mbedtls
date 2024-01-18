extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_ssl_read_record = [](mbedtls_ssl_context *ssl,
                                           unsigned update_hs_digest) {
  return nd_int();
};

extern "C" {
constexpr auto expectations_ssl_read_record =
    seamock::ExpectationBuilder().invokeFn(invoke_ssl_read_record).build();

MOCK_FUNCTION(mbedtls_ssl_read_record, expectations_ssl_read_record, int,
              (mbedtls_ssl_context *, unsigned));

LAZY_MOCK_FUNCTION(mbedtls_ssl_send_alert_message, int,
                   (mbedtls_ssl_context *, unsigned char, unsigned char))
}
