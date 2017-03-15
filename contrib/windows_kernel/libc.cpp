/**
 * @file libc.cpp
 * @author created by: Peter Hlavaty
 */

#include "libc.h"
#include <memory>
#include <Ntintsafe.h>

#pragma warning(push)               
#pragma warning (disable : 4565)

#ifndef _LIBC_POOL_TAG
#define _LIBC_POOL_TAG	'colM'
#endif

// very nice for debug forensics!
struct MEMBLOCK
{
	size_t	size;
#pragma warning(push)               
#pragma warning (disable : 4200)
	char data[0]; 
#pragma warning(pop)
};

EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(pBlock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* 
__cdecl malloc(
	__in size_t size
	)
{
	/* A specially crafted size value can trigger the overflow.
	If the sum in a value that overflows or underflows the capacity of the type,
	the function returns nullptr. */
	size_t number_of_bytes = 0;
	if (!NT_SUCCESS(RtlSizeTAdd(size, sizeof(MEMBLOCK), &number_of_bytes))){
		return nullptr;
	}
	MEMBLOCK *pBlock = static_cast<MEMBLOCK*>(
		ExAllocatePoolWithTag(
			NonPagedPoolNxCacheAligned, 
			number_of_bytes, 
			_LIBC_POOL_TAG));

	if (nullptr == pBlock)
		return nullptr;

	pBlock->size = size;	
	return pBlock->data;
}

EXTERN_C
__drv_when(return != 0, __drv_allocatesMem(p))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size * n)
void*
__cdecl calloc(size_t n, size_t size)
{
	size_t total = n * size;
	void *p = malloc(total);

	if (!p) return NULL;

	return memset(p, 0, total);
}

EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(inblock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* 
__cdecl realloc(
	__in_opt void* ptr, 
	__in size_t size
	)
{
	if (!ptr)
		return malloc(size);

	std::unique_ptr<unsigned char> inblock = std::unique_ptr<unsigned char>(static_cast<unsigned char*>(ptr));

	// alloc new block
	void* mem = malloc(size);
	if (!mem)
		return nullptr;

	// copy from old one, not overflow ..
	memcpy(mem, inblock.get(), min(CONTAINING_RECORD(inblock.get(), MEMBLOCK, data)->size, size));
	return mem;
}

EXTERN_C
__drv_maxIRQL(DISPATCH_LEVEL)
void 
__cdecl free(
	__inout_opt __drv_freesMem(Mem) void* ptr
	)
{
	if (ptr)
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, MEMBLOCK, data), _LIBC_POOL_TAG);
}

#pragma warning(pop)

__drv_when(return!=0, __drv_allocatesMem(ptr))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* 
__cdecl operator new(
	__in size_t size
	)
{
	return malloc(size);
}

__drv_maxIRQL(DISPATCH_LEVEL)
void 
__cdecl operator delete(
	__inout void* ptr
	)
{
	free(ptr);
}

int 
__cdecl vsnprintf(
	char *buffer,
	size_t count,
	const char *format,
	va_list argptr
)
{	
	return vsprintf_s(buffer, count, format, argptr);
}
