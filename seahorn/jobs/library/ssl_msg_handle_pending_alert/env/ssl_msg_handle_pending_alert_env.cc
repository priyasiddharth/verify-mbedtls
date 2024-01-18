extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_send_alert_message =
    [](mbedtls_ssl_context *ssl, unsigned char level, unsigned char message) {
      sassert(sea_is_dereferenceable(ssl->out_msg, 2));
      sassert(ssl->send_alert != 0);
      return nd_int();
    };

extern "C" {
// TODO: it is beneficial to have a conditional check such as
// if (ssl->send_alert != 0) then send_alert is called only once.
constexpr auto expectations_send_alert_message =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_send_alert_message)
        .times(seamock::Lt<2>())
        .build();

MOCK_FUNCTION(mbedtls_ssl_send_alert_message, expectations_send_alert_message,
              int, (mbedtls_ssl_context *, unsigned char, unsigned char))

SETUP_POST_CHECKS((mbedtls_ssl_send_alert_message))
}
