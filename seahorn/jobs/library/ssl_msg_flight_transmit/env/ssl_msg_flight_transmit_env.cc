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
size_t mbedtls_ssl_get_output_max_frag_len(const mbedtls_ssl_context *ssl) {
  size_t r = nd_size_t();
  assume(r <= ssl->out_msglen - 12);
  return r;
}
size_t mbedtls_ssl_get_current_mtu(const mbedtls_ssl_context *ssl) {
  size_t r = nd_size_t();
  assume(r <= ssl->out_msglen - 12);
  return r;
}
int mbedtls_ssl_get_record_expansion(const mbedtls_ssl_context *ssl) {
  int r = nd_int();
  assume(r <= ssl->out_msglen - 12);
  return r;
}
constexpr auto expectations_mbedtls_ssl_write_record =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_fn_mbedtls_ssl_write_record)
        .build();

MOCK_FUNCTION(mbedtls_ssl_write_record, expectations_mbedtls_ssl_write_record,
              int, (mbedtls_ssl_context *, int))

LAZY_MOCK_FUNCTION(mbedtls_ssl_flush_output, int, (mbedtls_ssl_context *))

LAZY_MOCK_FUNCTION(ssl_swap_epochs, int, (mbedtls_ssl_context *))

LAZY_MOCK_FUNCTION(mbedtls_ssl_update_out_pointers, void,
                   (mbedtls_ssl_context *, mbedtls_ssl_transform *))
}
