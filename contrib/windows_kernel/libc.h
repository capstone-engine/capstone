/**
 * @file libc.h
 * @author created by: Peter Hlavaty
 */

#pragma once

#include <ntifs.h>

EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(pBlock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* __cdecl malloc(__in size_t size);


EXTERN_C
__drv_when(return != 0, __drv_allocatesMem(p))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size * n)
void* __cdecl calloc(size_t n, size_t size);


EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(inblock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* __cdecl realloc(__in_opt void* ptr, __in size_t size);


EXTERN_C
__drv_maxIRQL(DISPATCH_LEVEL)
void __cdecl free(__inout_opt __drv_freesMem(Mem) void* ptr);


int __cdecl vsnprintf(char *buffer, size_t count,
	const char *format, va_list argptr);
