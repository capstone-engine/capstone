/* Capstone Driver */
/* By Satoshi Tanda <tanda.sat@gmail.com>, 2016-2019 */

// Firstly, compile capstone_static_winkernel and
// generate capstone_static_winkernel.lib. It can be done by adding the
// capstone_static_winkernel project to your solution and compiling it first.
//
// Then, configure your driver project (cs_driver in this example) to locate to
// capstone.h and capstone_static_winkernel.lib. To do it, open project
// properties of the project and set Configuration to "All Configurations" and
// Platform to "All Platforms". Then, add the following entries:
//    - C/C++ > General > Additional Include Directories
//      - $(SolutionDir)capstone\include
//    - C/C++ > Preprocessor > Preprocessor Definitions
//      - _NO_CRT_STDIO_INLINE
//    - Linker > Input > Additional Dependencies
//      - $(OutDir)capstone_static_winkernel.lib
//      - ntstrsafe.lib
//
// Note that ntstrsafe.lib is required to resolve __fltused indirectly used in
// Capstone.

#include <ntddk.h>
#include <capstone/capstone.h>

// 'conversion' : from function pointer 'type1' to data pointer 'type2'
#pragma warning(disable : 4054)


DRIVER_INITIALIZE DriverEntry;
static NTSTATUS cs_driver_hello();


// Driver entry point
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                              PUNICODE_STRING RegistryPath) {
  printf("Entering DriverEntry()\n");

  cs_driver_hello();

  printf("Leaving DriverEntry()\n");
  return STATUS_CANCELLED;
}

// Hello, Capstone!
static NTSTATUS cs_driver_hello() {
  csh handle;
  cs_insn *insn;
  size_t count;
  KFLOATING_SAVE float_save;
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  // Any of Capstone APIs cannot be called at IRQL higher than DISPATCH_LEVEL
  // since our malloc implementation based on ExAllocatePoolWithTag() is not able
  // to allocate memory at higher IRQL than the DISPATCH_LEVEL level.
  NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  // On a 32bit driver, KeSaveFloatingPointState() is required before using any
  // Capstone function because Capstone can access to the MMX/x87 registers and
  // 32bit Windows requires drivers to use KeSaveFloatingPointState() before and
  // KeRestoreFloatingPointState() after accessing them. See "Using Floating
  // Point or MMX in a WDM Driver" on MSDN for more details.
  status = KeSaveFloatingPointState(&float_save);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Do stuff just like user-mode. All functionalities are supported.
  if (cs_open(CS_ARCH_X86, (sizeof(void *) == 4) ? CS_MODE_32 : CS_MODE_64,
              &handle) != CS_ERR_OK) {
    goto exit;
  }

  count = cs_disasm(handle, (uint8_t *)&cs_driver_hello, 0x80,
                    (uint64_t)&cs_driver_hello, 0, &insn);
  if (count > 0) {
    printf("cs_driver!cs_driver_hello:\n");
    for (size_t j = 0; j < count; j++) {
      printf("0x%p\t%s\t\t%s\n", (void *)(uintptr_t)insn[j].address,
             insn[j].mnemonic, insn[j].op_str);
    }
    cs_free(insn, count);
  }
  cs_close(&handle);

exit:;
  // Restores the nonvolatile floating-point context.
  KeRestoreFloatingPointState(&float_save);
  return status;
}

// printf()
_Use_decl_annotations_ int __cdecl printf(const char * const _Format, ...) {
  NTSTATUS status;
  va_list args;

  va_start(args, _Format);
  status = vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, _Format, args);
  va_end(args);
  return NT_SUCCESS(status);
}
