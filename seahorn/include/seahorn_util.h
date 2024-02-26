#ifndef SEAHORN_UTIL_H_
#define SEAHORN_UTIL_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IS_ALIGN64(n) ((size_t)n << (sizeof(size_t) * 8 - 3)) == 0
#define ND_ALIGNED64_SIZE_T(var)                                               \
  size_t var = nd_size_t();                                                    \
  assume(IS_ALIGN64(var))

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
#ifndef TRACK_CUSTOM0_MEM
#define TRACK_CUSTOM0_MEM 3
#endif
// extern int nd_int(void);
extern size_t nd_size_t(void);
extern uint8_t nd_uint8_t(void);
extern bool nd_bool(void);
extern char nd_char(void);
extern int nd_int(void);
extern unsigned nd_uint32_t(void);
extern unsigned char nd_uchar(void);
extern void sea_reset_modified(char *);
extern bool sea_is_alloc(char *);
extern void sea_tracking_on(void);
extern void sea_tracking_off(void);
extern void sea_free(char *);
#ifdef __cplusplus
}
#endif

#endif // SEAHORN_UTIL_H_
