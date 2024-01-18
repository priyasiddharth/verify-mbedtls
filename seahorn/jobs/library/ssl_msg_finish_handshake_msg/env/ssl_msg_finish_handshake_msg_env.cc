extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

static size_t msg_len;

constexpr auto invoke_fn_mbedtls_ssl_write_handshake_msg_ext =
    [](mbedtls_ssl_context *ssl, int update_checksum, int force_flush) {
      sassert(ssl->out_msglen == 4 + msg_len);
      return nd_int();
    };

extern "C" {
void set_msg_len(size_t len) { msg_len = len; }
constexpr auto expectations_mbedtls_ssl_write_handshake_msg_ext =
    seamock::ExpectationBuilder()
        .times(seamock::Lt<2>())
        .invokeFn(invoke_fn_mbedtls_ssl_write_handshake_msg_ext)
        .build();

MOCK_FUNCTION(mbedtls_ssl_write_handshake_msg_ext,
              expectations_mbedtls_ssl_write_handshake_msg_ext, int,
              (mbedtls_ssl_context *, int, int))
SETUP_POST_CHECKS((mbedtls_ssl_write_handshake_msg_ext))
}
