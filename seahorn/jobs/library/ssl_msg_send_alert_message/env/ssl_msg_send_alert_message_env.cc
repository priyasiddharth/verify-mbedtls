extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

static unsigned char level;
static unsigned char message;

constexpr auto invoke_fn_mbedtls_ssl_write_record = [](mbedtls_ssl_context *ssl,
                                                       int force_flush) {
  size_t len = ssl->out_msglen;
  unsigned char *out_msg = ssl->out_msg;
  if (out_msg != NULL) {
    sassert(sea_is_dereferenceable(out_msg, len));
  }
  sassert(ssl->out_msgtype == MBEDTLS_SSL_MSG_ALERT);
  sassert(ssl->out_msglen == 2);
  sassert(ssl->out_msg[0] == level);
  sassert(ssl->out_msg[1] == message);
  return nd_int();
};

extern "C" {
void set_alert_msg_params(unsigned char lvl, unsigned char msg) {
  level = lvl;
  message = msg;
}

constexpr auto expectations_mbedtls_ssl_write_record =
    MakeExpectation(Expect(InvokeFn, invoke_fn_mbedtls_ssl_write_record));

MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_mbedtls_ssl_write_record,
              int, (mbedtls_ssl_context *, int))

LAZY_MOCK_FUNCTION(mbedtls_ssl_flush_output, int, (mbedtls_ssl_context *))
}
