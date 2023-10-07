extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

#define INLINE __attribute__((always_inline))

extern "C" {
// The use of inline attribute clashes with MOCK_FUNCTION def so
// using plain old functiond def.
INLINE int bcmp(const void *s1, const void *s2, size_t n) {
  sassert(sea_is_dereferenceable(s1, n));
  sassert(sea_is_dereferenceable(s2, n));
  return nd_int();
}

LAZY_MOCK_FUNCTION(mbedtls_ssl_resend, int, (mbedtls_ssl_context *))
}
