extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>
#include <string.h>


constexpr auto invoke_calloc = [](size_t number, size_t size) {
  //sassert(size <= GLOBAL_BUF_MAX_SIZE);
  void *ptr = nd_bool() ? NULL : malloc(size);
  if (ptr == NULL) return ptr;  
  // memhavoc(ptr, size);
  memset(ptr, number, size);
  return ptr;
};

constexpr auto invoke_objcopy = [](void * dst, void * src, size_t n) {  
  void *r = memcpy(dst, src, n);
  return r;
};

extern "C" {
constexpr auto expectations_calloc =
    seamock::ExpectationBuilder().invokeFn(invoke_calloc).build();
MOCK_FUNCTION(calloc, expectations_calloc, void *, (size_t, size_t));
constexpr auto expectations_objcopy =
    seamock::ExpectationBuilder().invokeFn(invoke_objcopy).build();
MOCK_FUNCTION(objcopy, expectations_objcopy, void *, (void *, void *, size_t));
}