#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"

#include <seahorn/seahorn.h>
// #include <seahorn_util.h>
#include <seamock.hh>

extern "C" {

extern int nd_int(void);
}

constexpr auto ret_fn_mbedtls_ssl_write_record = []() { return nd_int(); };

// Check ssl msg is correct
constexpr auto check_arg_mbedtls_ssl_write_record =
    [](mbedtls_ssl_context *ssl) {
      sassert(ssl->out_msgtype == MBEDTLS_SSL_MSG_ALERT);
      sassert(ssl->out_msglen == 2);
      sassert(ssl->out_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING);
      sassert(ssl->out_msg[1] == MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY);
    };

constexpr auto capture_map_mbedtls_ssl_write_record = hana::make_map(
    hana::make_pair(hana::size_c<0>, check_arg_mbedtls_ssl_write_record));

extern "C" {
constexpr auto expectations_mbed_write_record =
    MakeExpectation(Expect(Times, Lt(2_c)) ^ AND ^
                    Expect(ReturnFn, ret_fn_mbedtls_ssl_write_record) ^ AND ^
                    Expect(Capture, capture_map_mbedtls_ssl_write_record));

MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_mbed_write_record, int,
              (mbedtls_ssl_context *, int))

LAZY_MOCK_FUNCTION(mbedtls_ssl_flush_output, int, (mbedtls_ssl_context *))

SETUP_POST_CHECKS((mbedtls_ssl_write_record))
}
