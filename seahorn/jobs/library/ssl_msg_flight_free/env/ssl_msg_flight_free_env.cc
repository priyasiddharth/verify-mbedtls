extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_fn_mbedtls_free = [](void *ptr) {
  sassert(sea_is_alloc((char *)ptr));
  sea_free((char *)ptr);
};

extern "C" {
constexpr auto expectations_mbedtls_free =
    MakeExpectation(Expect(InvokeFn, invoke_fn_mbedtls_free));

MOCK_FUNCTION(free, expectations_mbedtls_free, void, (void *))
}
