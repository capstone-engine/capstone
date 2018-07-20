/* Capstone Disassembly Engine */
/* By Satoshi Tanda <tanda.sat@gmail.com>, 2016 */

#include <ntddk.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../utils.h"   // for cs_snprintf

#ifdef __cplusplus
}
#endif

EXTERN_C DRIVER_INITIALIZE DriverEntry;

#pragma warning(push)
#pragma warning(disable : 4005)   // 'identifier' : macro redefinition
#pragma warning(disable : 4007)   // 'main': must be '__cdecl'

// Drivers must protect floating point hardware state. See use of float.
// Use KeSaveFloatingPointState/KeRestoreFloatingPointState around floating
// point operations. Display Drivers should use the corresponding Eng... routines.
#pragma warning(disable : 28110)  // Suppress this, as it is false positive.

// "Import" existing tests into this file. All code is encaptured into unique
// namespace so that the same name does not conflict. Beware that those code
// is going to be compiled as C++ source file and not C files because this file
// is C++.

namespace basic {
#include "test_basic.c"
}  // namespace basic

namespace detail {
#include "test_detail.c"
}  // namespace detail

namespace skipdata {
#include "test_skipdata.c"
}  // namespace skipdata

namespace iter {
#include "test_iter.c"
}  // namespace iter

namespace customized_mnem_ {
#include "test_customized_mnem.c"
}  // namespace customized_mnem_

namespace arm {
#include "test_arm.c"
}  // namespace arm

namespace arm64 {
#include "test_arm64.c"
}  // namespace arm64

namespace mips {
#include "test_mips.c"
}  // namespace mips

namespace m68k {
#include "test_m68k.c"
}  // namespace m68k

namespace ppc {
#include "test_ppc.c"
}  // namespace ppc

namespace sparc {
#include "test_sparc.c"
}  // namespace sparc

namespace systemz {
#include "test_systemz.c"
}  // namespace systemz

namespace x86 {
#include "test_x86.c"
}  // namespace x86

namespace xcore {
#include "test_xcore.c"
}  // namespace xcore

#pragma warning(pop)

// Exercises all existing regression tests
static void test()
{
	KFLOATING_SAVE float_save;
	NTSTATUS status;

	// Any of Capstone APIs cannot be called at IRQL higher than DISPATCH_LEVEL
	// since our malloc implementation using ExAllocatePoolWithTag() is able to
	// allocate memory only up to the DISPATCH_LEVEL level.
	NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	// On a 32bit driver, KeSaveFloatingPointState() is required before using any
	// Capstone function because Capstone can access to the MMX/x87 registers and
	// 32bit Windows requires drivers to use KeSaveFloatingPointState() before and
	// KeRestoreFloatingPointState() after accessing them. See "Using Floating
	// Point or MMX in a WDM Driver" on MSDN for more details.
	status = KeSaveFloatingPointState(&float_save);
	if (!NT_SUCCESS(status)) {
		printf("ERROR: Failed to save floating point state!\n");
		return;
	}

	basic::test();
	detail::test();
	skipdata::test();
	iter::test();
	customized_mnem_::test();
	arm::test();
	arm64::test();
	mips::test();
	m68k::test();
	ppc::test();
	sparc::test();
	systemz::test();
	x86::test();
	xcore::test();

	// Restores the nonvolatile floating-point context.
	KeRestoreFloatingPointState(&float_save);
}

// Functional test for cs_winkernel_vsnprintf()
static void cs_winkernel_vsnprintf_test()
{
	char buf[10];
	bool ok = true;
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "") == 0 && strcmp(buf, "") == 0);
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "0") == 1 && strcmp(buf, "0") == 0);
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "012345678") == 9 && strcmp(buf, "012345678") == 0);
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "0123456789") == 10 && strcmp(buf, "012345678") == 0);
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "01234567890") == 11 && strcmp(buf, "012345678") == 0);
	ok = (ok && cs_snprintf(buf, sizeof(buf), "%s", "0123456789001234567890") == 22 && strcmp(buf, "012345678") == 0);
	if (!ok) {
		printf("ERROR: cs_winkernel_vsnprintf_test() did not produce expected results!\n");
	}
}

// Driver entry point
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	cs_winkernel_vsnprintf_test();
	test();
	return STATUS_CANCELLED;
}

// This functions mimics printf() but does not return the same value as printf()
// would do. printf() is required to exercise regression tests.
_Use_decl_annotations_
int __cdecl printf(const char * format, ...)
{
	NTSTATUS status;
	va_list args;

	va_start(args, format);
	status = vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, format, args);
	va_end(args);
	return NT_SUCCESS(status);
}
