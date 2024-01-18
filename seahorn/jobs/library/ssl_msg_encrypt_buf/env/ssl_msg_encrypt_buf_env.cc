extern "C" {
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

// Mocking for mbedtls_cipher_auth_encrypt_ext
constexpr auto invoke_mbedtls_cipher_auth_encrypt_ext =
    [](mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len,
       const unsigned char *additional_data, size_t additional_data_len,
       const unsigned char *input, size_t ilen, unsigned char *output,
       size_t olen, size_t *olen_out, size_t tag_len) {
      sassert(ctx != nullptr);
      sassert(iv != nullptr);
      sassert(additional_data != nullptr);
      sassert(input != nullptr);
      sassert(output != nullptr);
      sassert(olen_out != nullptr);
      return nd_int(); // Return non-deterministic integer to simulate possible
                       // return values of the real function.
    };

constexpr auto invoke_mbedtls_cipher_crypt =
    [](mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len,
       const unsigned char *input, size_t ilen, unsigned char *output,
       size_t *olen) {
      sassert(ctx != nullptr);
      sassert(iv != nullptr);
      sassert(input != nullptr);
      sassert(output != nullptr);
      sassert(olen != nullptr);
      return nd_int(); // Return non-deterministic integer to simulate possible
                       // return values of the real function.
    };

// Mocking for mbedtls_platform_zeroize
constexpr auto invoke_mbedtls_platform_zeroize = [](void *buf, size_t len) {};

extern "C" {
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
