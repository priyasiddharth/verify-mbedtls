extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

auto ssl_get_remaining_space_in_datagram_invoke =
    [](mbedtls_ssl_context const *ssl) {

    };

constexpr auto invoke_fn_mbedtls_ssl_send_t =
    [](void *ctx, const unsigned char *buf, size_t len) {
      sassert(sea_is_dereferenceable(buf, len));
      return nd_int();
    };

constexpr auto expectations_mbedtls_ssl_send_t =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_fn_mbedtls_ssl_send_t)
        .build();

// Mocking for mbedtls_cipher_auth_encrypt_ext
constexpr auto invoke_mbedtls_cipher_auth_encrypt_ext =
    [](mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len,
       const unsigned char *additional_data, size_t additional_data_len,
       const unsigned char *input, size_t ilen, unsigned char *output,
       size_t olen, size_t *olen_out, size_t tag_len) {
      
      /* sassert(ctx != nullptr);
      sassert(iv != nullptr);
      sassert(additional_data != nullptr);
      sassert(input != nullptr);
      sassert(output != nullptr);
      sassert(olen_out != nullptr); */
      sea_set_shadowmem(3, (char *)output, 1);

      return nd_int(); // Return non-deterministic integer to simulate possible
                       // return values of the real function.
    };

constexpr auto invoke_mbedtls_cipher_crypt =
    [](mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len,
       const unsigned char *input, size_t ilen, unsigned char *output,
       size_t *olen) {
      sea_tracking_on(); 
      /* sassert(ctx != nullptr);
      sassert(iv != nullptr);
      sassert(input != nullptr);
      sassert(output != nullptr);
      sassert(olen != nullptr); */
      sea_set_shadowmem(3, (char *)output, 1);
      return nd_int(); // Return non-deterministic integer to simulate possible
                       // return values of the real function.
    };

constexpr auto invoke_mbedtls_platform_zeroize = [](void *buf, size_t len) {};


constexpr auto invoke_fn_mbedtls_ssl_flush_output = [](mbedtls_ssl_context *ssl) {
  size_t count = sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf));
  sea_printf("ssl.out_buf:%x\n", ssl->out_buf);

  while (count > 0 && count < 8) {
    count++;
    sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *)(ssl->out_buf), count);          
  }
  size_t count_ptr = 0;  
  SEA_READ_CACHE(count_ptr, ssl->out_buf); 
  while (count_ptr > 0 && count_ptr < 8) {
    count_ptr++;
    SEA_WRITE_CACHE(ssl->out_buf, count_ptr);
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

MOCK_FUNCTION(send_fn, expectations_mbedtls_ssl_send_t, int,
              (void * /* ctx */, const unsigned char * /* buf */,
               size_t /* len */))

constexpr auto expect_mbedtls_cipher_auth_encrypt_ext =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_mbedtls_cipher_auth_encrypt_ext)
        .build();
MOCK_FUNCTION(mbedtls_cipher_auth_encrypt_ext,
              expect_mbedtls_cipher_auth_encrypt_ext, int,
              (mbedtls_cipher_context_t *, const unsigned char *, size_t,
               const unsigned char *, size_t, const unsigned char *, size_t,
               unsigned char *, size_t, size_t *, size_t))

constexpr auto expect_mbedtls_cipher_crypt =
    seamock::ExpectationBuilder().invokeFn(invoke_mbedtls_cipher_crypt).build();
MOCK_FUNCTION(mbedtls_cipher_crypt, expect_mbedtls_cipher_crypt, int,
              (mbedtls_cipher_context_t *, const unsigned char *, size_t,
               const unsigned char *, size_t, unsigned char *, size_t *))

constexpr auto expect_mbedtls_platform_zeroize =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_mbedtls_platform_zeroize)
        .build();
MOCK_FUNCTION(mbedtls_platform_zeroize, expect_mbedtls_platform_zeroize, void,
              (void *, size_t))               
}
