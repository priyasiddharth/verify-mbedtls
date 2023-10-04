extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_ct_memcmp = [](const void *a, const void *b, size_t n) {
  sassert(sea_is_dereferenceable(a, n));
  sassert(sea_is_dereferenceable(b, n));
  return nd_int();
};

extern "C" {

constexpr auto expect_ct_memcmp =
    MakeExpectation(Expect(InvokeFn, invoke_ct_memcmp));

MOCK_FUNCTION(mbedtls_ct_memcmp, expect_ct_memcmp, int,
              (const void *, const void *, size_t))
SUC_MOCK_FUNCTION(mbedtls_cipher_auth_decrypt_ext,
                  (mbedtls_cipher_context_t *, const unsigned char *, size_t,
                   const unsigned char *, size_t, const unsigned char *, size_t,
                   unsigned char *, size_t, size_t *, size_t))
#if defined(MBEDTLS_USE_PSA_CRYPTO)
SUC_MOCK_FUNCTION(psa_aead_decrypt,
                  (psa_key_handle_t, psa_algorithm_t, const unsigned char *,
                   size_t, const unsigned char *, size_t, const unsigned char *,
                   size_t, unsigned char *, size_t, size_t *))
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
SUC_MOCK_FUNCTION(mbedtls_ct_hmac,
                  (psa_key_handle_t, psa_algorithm_t, const unsigned char *,
                   size_t, const unsigned char *, size_t, size_t, size_t,
                   unsigned char *))
#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
SUC_MOCK_FUNCTION(mbedtls_md_hmac_update,
                  (mbedtls_md_context_t *, const unsigned char *, size_t))
SUC_MOCK_FUNCTION(mbedtls_md_hmac_finish,
                  (mbedtls_md_context_t *, unsigned char *))
SUC_MOCK_FUNCTION(mbedtls_md_hmac_reset, (mbedtls_md_context_t *))
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
ERR_SUC_MOCK_FUNCTION(psa_cipher_decrypt_setup,
                      (psa_cipher_operation_t *, psa_key_handle_t,
                       psa_algorithm_t))
ERR_SUC_MOCK_FUNCTION(psa_cipher_set_iv,
                      (psa_cipher_operation_t *, const unsigned char *, size_t))
ERR_SUC_MOCK_FUNCTION(psa_cipher_update,
                      (psa_cipher_operation_t *, const unsigned char *, size_t,
                       unsigned char *, size_t, size_t *))
ERR_SUC_MOCK_FUNCTION(psa_cipher_finish, (psa_cipher_operation_t *,
                                          unsigned char *, size_t, size_t *))
#endif
LAZY_MOCK_FUNCTION(ssl_build_record_nonce, void,
                   (unsigned char *, size_t, unsigned char const *, size_t,
                    unsigned char const *, size_t))
ERR_SUC_MOCK_FUNCTION(ssl_parse_inner_plaintext,
                      (unsigned char const *, size_t *, uint8_t *))
}
