extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>
#include <string.h>

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

constexpr auto invoke_fn_mbedtls_ssl_flush_output = [](mbedtls_ssl_context *ssl) {
  int r = nd_int();
  assume(r <= 0);
  SEA_DIE(ssl);
  return r;  
};

constexpr auto invoke_objcopy = [](void *__restrict dst, const void *__restrict src, size_t n) {
  SEA_WRITE_CACHE(dst, (size_t) src);
  SEA_WRITE_CACHE(src, (size_t) dst);
  //sea_printf("src_count(2):%ld\n", src_count + 1);
  //sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) src, (size_t) dst);
  //sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) dst, (size_t) src);
  void * r = memcpy(dst, src, n);
  SEA_DIE(src);
  SEA_DIE(dst);
  return r;
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

SUC_MOCK_FUNCTION(mbedtls_ssl_write_version,
                  (unsigned char *, int, mbedtls_ssl_protocol_version))

ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_space_in_datagram,
                      (mbedtls_ssl_context *))
ERR_SUC_MOCK_FUNCTION(ssl_get_remaining_payload_in_datagram,
                      (mbedtls_ssl_context *))


constexpr auto expectations_mbedtls_ssl_flush_output =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_fn_mbedtls_ssl_flush_output)
        .build();

MOCK_FUNCTION(mbedtls_ssl_flush_output, expectations_mbedtls_ssl_flush_output, int, (mbedtls_ssl_context *));

constexpr auto expectations_objcopy =
    seamock::ExpectationBuilder().invokeFn(invoke_objcopy).build();
MOCK_FUNCTION(objcopy, expectations_objcopy, void *, (void *__restrict, const void * __restrict, size_t));

//SETUP_POST_CHECKS((mbedtls_ssl_write_record))
}
