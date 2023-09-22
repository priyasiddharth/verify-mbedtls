#ifndef SEAHORN_UTIL_H_
#define SEAHORN_UTIL_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ND __declspec(noalias)
/*
** memhaovoc havocs a contiguous number of bytes starting at ptr upto length
** size. Note that if the bytes represent a pointer then in the LLVM model, this
** pointer cannot point to any allocation created using malloc.
**
** This is because each malloc always gives a fresh location. This implies that
** one cannot havoc a pointer and then assume it is equal to another pointer
** created using malloc.
*/
extern ND void memhavoc(void *ptr, size_t size);
extern ND void sea_printf(const char *format, ...);

extern int nd_int(void);
extern size_t nd_size_t(void);
extern uint8_t nd_uint8_t(void);
extern bool nd_bool(void);
#ifdef __cplusplus
}
#endif

#endif // SEAHORN_UTIL_H_
