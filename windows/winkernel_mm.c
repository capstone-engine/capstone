/* Capstone Disassembly Engine */
/* By Satoshi Tanda <tanda.sat@gmail.com>, 2016-2019 */

#include "winkernel_mm.h"
#include <ntddk.h>
#include <Ntintsafe.h>

// A pool tag for memory allocation
static const ULONG CS_WINKERNEL_POOL_TAG = 'kwsC';


// A structure to implement realloc()
typedef struct _CS_WINKERNEL_MEMBLOCK {
	size_t size;   // A number of bytes allocated
	__declspec(align(MEMORY_ALLOCATION_ALIGNMENT))
	char data[ANYSIZE_ARRAY];  // An address returned to a caller
} CS_WINKERNEL_MEMBLOCK;


// free()
void CAPSTONE_API cs_winkernel_free(void *ptr)
{
	if (ptr) {
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, CS_WINKERNEL_MEMBLOCK, data), CS_WINKERNEL_POOL_TAG);
	}
}

// malloc()
void * CAPSTONE_API cs_winkernel_malloc(size_t size)
{
	// Disallow zero length allocation because they waste pool header space and,
	// in many cases, indicate a potential validation issue in the calling code.
	NT_ASSERT(size);

	// FP; a use of NonPagedPool is required for Windows 7 support
	size_t number_of_bytes = 0;
	CS_WINKERNEL_MEMBLOCK *block = NULL;
	// A specially crafted size value can trigger the overflow.
	// If the sum in a value that overflows or underflows the capacity of the type,
	// the function returns NULL.
	if (!NT_SUCCESS(RtlSizeTAdd(size, FIELD_OFFSET(CS_WINKERNEL_MEMBLOCK, data), &number_of_bytes))) {
		return NULL;
	}
#pragma prefast(suppress : 30030)		// Allocating executable POOL_TYPE memory
	block = (CS_WINKERNEL_MEMBLOCK *)ExAllocatePoolWithTag(
			NonPagedPool, number_of_bytes, CS_WINKERNEL_POOL_TAG);
	if (!block) {
		return NULL;
	}
	block->size = size;

	return block->data;
}

// calloc()
void * CAPSTONE_API cs_winkernel_calloc(size_t n, size_t size)
{
	size_t total = n * size;

	void *new_ptr = cs_winkernel_malloc(total);
	if (!new_ptr) {
		return NULL;
	}

	return RtlFillMemory(new_ptr, total, 0);
}

// realloc()
void * CAPSTONE_API cs_winkernel_realloc(void *ptr, size_t size)
{
	void *new_ptr = NULL;
	size_t current_size = 0;
	size_t smaller_size = 0;

	if (!ptr) {
		return cs_winkernel_malloc(size);
	}

	new_ptr = cs_winkernel_malloc(size);
	if (!new_ptr) {
		return NULL;
	}

	current_size = CONTAINING_RECORD(ptr, CS_WINKERNEL_MEMBLOCK, data)->size;
	smaller_size = (current_size < size) ? current_size : size;
	RtlCopyMemory(new_ptr, ptr, smaller_size);
	cs_winkernel_free(ptr);

	return new_ptr;
}

// vsnprintf(). _vsnprintf() is available for drivers, but it differs from
// vsnprintf() in a return value and when a null-terminator is set.
// cs_winkernel_vsnprintf() takes care of those differences.
#pragma warning(push)
// Banned API Usage : _vsnprintf is a Banned API as listed in dontuse.h for
// security purposes.
#pragma warning(disable : 28719)
int CAPSTONE_API cs_winkernel_vsnprintf(char *buffer, size_t count, const char *format, va_list argptr)
{
	int result = _vsnprintf(buffer, count, format, argptr);

	// _vsnprintf() returns -1 when a string is truncated, and returns "count"
	// when an entire string is stored but without '\0' at the end of "buffer".
	// In both cases, null-terminator needs to be added manually.
	if (result == -1 || (size_t)result == count) {
		buffer[count - 1] = '\0';
	}

	if (result == -1) {
		// In case when -1 is returned, the function has to get and return a number
		// of characters that would have been written. This attempts so by retrying
		// the same conversion with temp buffer that is most likely big enough to
		// complete formatting and get a number of characters that would have been
		// written.
		char* tmp = cs_winkernel_malloc(0x1000);
		if (!tmp) {
			return result;
		}

		result = _vsnprintf(tmp, 0x1000, format, argptr);
		NT_ASSERT(result != -1);
		cs_winkernel_free(tmp);
	}

	return result;
}
#pragma warning(pop)
