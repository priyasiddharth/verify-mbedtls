extern "C" {
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

// Mocking for mbedtls_platform_zeroize
constexpr auto invoke_mbedtls_platform_zeroize = [](void *buf, size_t len) {
  if (buf != NULL) {
    sassert(sea_is_dereferenceable(buf, len));
  }
};

extern "C" {
auto expect_mbedtls_platform_zeroize =
    seamock::ExpectationBuilder()
        .invokeFn(invoke_mbedtls_platform_zeroize)
        .times(seamock::Lt<2>())
        .build();
MOCK_FUNCTION(mbedtls_platform_zeroize, expect_mbedtls_platform_zeroize, void,
              (void *, size_t))
}
