extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>

constexpr auto invoke_zeroize_and_free_fn = [](void *buf, size_t len) {
  sassert(sea_is_dereferenceable(buf, len));
};

constexpr auto expectations_zeroize_and_free =
    MakeExpectation(Expect(InvokeFn, invoke_zeroize_and_free_fn));

extern "C" {
MOCK_FUNCTION(mbedtls_zeroize_and_free, expectations_zeroize_and_free, void,
              (void * /* buf */, size_t /* len */))
}
