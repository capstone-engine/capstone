/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2016 */
#ifndef CS_WINDOWS_WINKERNEL_MM_H_
#define CS_WINDOWS_WINKERNEL_MM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <capstone.h>

void CAPSTONE_API cs_winkernel_free(void *ptr);
void * CAPSTONE_API cs_winkernel_malloc(size_t size);
void * CAPSTONE_API cs_winkernel_calloc(size_t n, size_t size);
void * CAPSTONE_API cs_winkernel_realloc(void *ptr, size_t size);
int CAPSTONE_API cs_winkernel_vsnprintf(char *buffer, size_t count, const char *format, va_list argptr);

#ifdef __cplusplus
}
#endif

#endif  // CS_WINDOWS_WINKERNEL_MM_H_
