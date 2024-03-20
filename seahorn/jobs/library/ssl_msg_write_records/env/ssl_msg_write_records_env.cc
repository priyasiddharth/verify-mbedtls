extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

/* Length of the "epoch" field in the record header */
static inline size_t mbedtls_ssl_ep_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 2;
    }
#else
    ((void) ssl);
#endif
    return 0;
}

constexpr auto invoke_fn_mbedtls_ssl_flush_output = [](mbedtls_ssl_context *ssl) {
  size_t count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf));
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);
  size_t shift = 0;
  if (count > 0) {
    size_t counter = 0;
    for (size_t i = 8; i > mbedtls_ssl_ep_len(ssl); i--) {
      counter = ((size_t)ssl->cur_out_ctr[i - 1] << shift) | counter;
      shift+=8;
    }
    sea_printf("Counter(flush) addr:%x]n", ssl->cur_out_ctr);
    sea_printf("counter(flush) val:%d\n", counter);
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf), counter);
  }
  int r = nd_int();
  assume(r == 0);
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
