extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_fn_mbedtls_ssl_flush_output = [](mbedtls_ssl_context *ssl) {
  size_t count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf));
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);

  while (count > 0 && count < 8) {
    count++;
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf), count);          
  }
  int r = nd_int();
  assume(r <= 0);
  return r;  
};

constexpr auto expectations_mbedtls_ssl_flush_output =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_fn_mbedtls_ssl_flush_output)
        .build();

extern "C" {
SUC_MOCK_FUNCTION(mbedtls_ssl_write_version,
                  (unsigned char *, int, mbedtls_ssl_protocol_version))

ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_space_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_payload_in_datagram,
                      (mbedtls_ssl_context *))
MOCK_FUNCTION(mbedtls_ssl_flush_output, expectations_mbedtls_ssl_flush_output, int, (mbedtls_ssl_context *));
}
