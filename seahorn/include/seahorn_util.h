#ifndef SEAHORN_UTIL_H_
#define SEAHORN_UTIL_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ND __declspec(noalias)

extern ND void memhavoc(void *ptr, size_t size);

extern int nd_int(void);
extern size_t nd_size_t(void);
extern uint8_t nd_uint8_t(void);
#ifdef __cplusplus
}
#endif

#endif // SEAHORN_UTIL_H_
