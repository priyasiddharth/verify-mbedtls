extern "C" { // C linkage: The decl of mock fn and def should have same linkage
#include "common.h" // allow access to private members of ssl_context
#include "mbedtls/ssl.h"
}
#include <seahorn/seahorn.h>
#include <seahorn_util.h>
#include <seamock.hh>
#include <string.h>

constexpr auto invoke_objcopy = [](void * dst, void * src, size_t n) {
  //   size_t src_count, dst_count;
  //   SEA_READ_CACHE(dst_count, dst);
  //   SEA_READ_CACHE(src_count, src); 
  //   SEA_WRITE_CACHE(dst, dst_count + 1);
  //   SEA_WRITE_CACHE(src, src_count + 1);
  //   sea_printf("src_count(2):%ld\n", src_count + 1);
  //sea_set_shadowmem(TRACK_CUSTOM0_MEM, (char *) src, 
  //      sea_get_shadowmem(TRACK_CUSTOM0_MEM, (char *) src) + 1);
  void * r = memcpy(dst, src, n);
  SEA_DIE(src);
  SEA_DIE(dst);
  return r;
};


constexpr auto invoke_calloc = [](size_t number, size_t size) {
  //sassert(size <= GLOBAL_BUF_MAX_SIZE);
  void *ptr = nd_bool() ? NULL : malloc(size);
  if (ptr == NULL) return ptr;
  // memhavoc(ptr, size);
  memset(ptr, number, size);
  return ptr;
};

extern "C" {
constexpr auto expectations_calloc =
    seamock::ExpectationBuilder().invokeFn(invoke_calloc).build();
MOCK_FUNCTION(calloc, expectations_calloc, void *, (size_t, size_t));
constexpr auto expectations_objcopy =
    seamock::ExpectationBuilder().invokeFn(invoke_objcopy).build();
MOCK_FUNCTION(objcopy, expectations_objcopy, void *, (void *, void *, size_t));
}