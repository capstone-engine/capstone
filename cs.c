/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
#ifdef _MSC_VER
#pragma warning(disable:4996)			// disable MSVC's warning on strcpy()
#pragma warning(disable:28719)		// disable MSVC's warning on strcpy()
#endif
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <string.h>
#include <capstone/capstone.h>

#include "utils.h"
#include "MCRegisterInfo.h"

#if defined(_KERNEL_MODE)
#include "windows\winkernel_mm.h"
#endif

// Issue #681: Windows kernel does not support formatting float point
#if defined(_KERNEL_MODE) && !defined(CAPSTONE_DIET)
#if defined(CAPSTONE_HAS_ARM) || defined(CAPSTONE_HAS_AARCH64) || defined(CAPSTONE_HAS_M68K)
#define CAPSTONE_STR_INTERNAL(x) #x
#define CAPSTONE_STR(x) CAPSTONE_STR_INTERNAL(x)
#define CAPSTONE_MSVC_WRANING_PREFIX __FILE__ "("CAPSTONE_STR(__LINE__)") : warning message : "

#pragma message(CAPSTONE_MSVC_WRANING_PREFIX "Windows driver does not support full features for selected architecture(s). Define CAPSTONE_DIET to compile Capstone with only supported features. See issue #681 for details.")

#undef CAPSTONE_MSVC_WRANING_PREFIX
#undef CAPSTONE_STR
#undef CAPSTONE_STR_INTERNAL
#endif
#endif	// defined(_KERNEL_MODE) && !defined(CAPSTONE_DIET)

#if !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(CAPSTONE_DIET) && !defined(_KERNEL_MODE)
#define INSN_CACHE_SIZE 32
#else
// reduce stack variable size for kernel/firmware
#define INSN_CACHE_SIZE 8
#endif

// default SKIPDATA mnemonic
#ifndef CAPSTONE_DIET
#define SKIPDATA_MNEM ".byte"
#else // No printing is available in diet mode
#define SKIPDATA_MNEM NULL
#endif

#include "arch/AArch64/AArch64Module.h"
#include "arch/ARM/ARMModule.h"
#include "arch/EVM/EVMModule.h"
#include "arch/WASM/WASMModule.h"
#include "arch/M680X/M680XModule.h"
#include "arch/M68K/M68KModule.h"
#include "arch/Mips/MipsModule.h"
#include "arch/PowerPC/PPCModule.h"
#include "arch/Sparc/SparcModule.h"
#include "arch/SystemZ/SystemZModule.h"
#include "arch/TMS320C64x/TMS320C64xModule.h"
#include "arch/X86/X86Module.h"
#include "arch/XCore/XCoreModule.h"
#include "arch/RISCV/RISCVModule.h"
#include "arch/MOS65XX/MOS65XXModule.h"
#include "arch/BPF/BPFModule.h"
#include "arch/SH/SHModule.h"
#include "arch/TriCore/TriCoreModule.h"
#include "arch/Alpha/AlphaModule.h"
#include "arch/HPPA/HPPAModule.h"

typedef struct cs_arch_config {
	// constructor initialization
	cs_err (*arch_init)(cs_struct *);
	// support cs_option()
	cs_err (*arch_option)(cs_struct *, cs_opt_type, size_t value);
	// bitmask for finding disallowed modes for an arch:
	// to be called in cs_open()/cs_option()
	cs_mode arch_disallowed_mode_mask;
} cs_arch_config;

#define CS_ARCH_CONFIG_ARM \
	{ \
		ARM_global_init, \
		ARM_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM | CS_MODE_V8 | CS_MODE_MCLASS | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_AARCH64 \
	{ \
		AArch64_global_init, \
		AArch64_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM | CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_MIPS \
	{ \
		Mips_global_init, \
		Mips_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_32 | CS_MODE_64 | CS_MODE_MICRO \
			| CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN | CS_MODE_MIPS2 | CS_MODE_MIPS3), \
	}
#define CS_ARCH_CONFIG_X86 \
	{ \
		X86_global_init, \
		X86_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_32 | CS_MODE_64 | CS_MODE_16), \
	}
#define CS_ARCH_CONFIG_PPC \
	{ \
		PPC_global_init, \
		PPC_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_32 | CS_MODE_64 | CS_MODE_BIG_ENDIAN \
				| CS_MODE_QPX | CS_MODE_PS | CS_MODE_BOOKE), \
	}
#define CS_ARCH_CONFIG_SPARC \
	{ \
		Sparc_global_init, \
		Sparc_option, \
		~(CS_MODE_BIG_ENDIAN | CS_MODE_V9), \
	}
#define CS_ARCH_CONFIG_SYSZ \
	{ \
		SystemZ_global_init, \
		SystemZ_option, \
		~(CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_XCORE \
	{ \
		XCore_global_init, \
		XCore_option, \
		~(CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_M68K \
	{ \
		M68K_global_init, \
		M68K_option, \
		~(CS_MODE_BIG_ENDIAN | CS_MODE_M68K_000 | CS_MODE_M68K_010 | CS_MODE_M68K_020 \
				| CS_MODE_M68K_030 | CS_MODE_M68K_040 | CS_MODE_M68K_060), \
	}
#define CS_ARCH_CONFIG_TMS320C64X \
	{ \
		TMS320C64x_global_init, \
		TMS320C64x_option, \
		~(CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_M680X \
	{ \
		M680X_global_init, \
		M680X_option, \
		~(CS_MODE_M680X_6301 | CS_MODE_M680X_6309 | CS_MODE_M680X_6800 \
				| CS_MODE_M680X_6801 | CS_MODE_M680X_6805 | CS_MODE_M680X_6808 \
				| CS_MODE_M680X_6809 | CS_MODE_M680X_6811 | CS_MODE_M680X_CPU12 \
				| CS_MODE_M680X_HCS08), \
	}
#define CS_ARCH_CONFIG_EVM \
	{ \
		EVM_global_init, \
		EVM_option, \
		0, \
	}
#define CS_ARCH_CONFIG_MOS65XX \
	{ \
		MOS65XX_global_init, \
		MOS65XX_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_MOS65XX_6502 | CS_MODE_MOS65XX_65C02 \
				| CS_MODE_MOS65XX_W65C02 | CS_MODE_MOS65XX_65816_LONG_MX), \
	}
#define CS_ARCH_CONFIG_WASM \
	{ \
		WASM_global_init, \
		WASM_option, \
		0, \
	}
#define CS_ARCH_CONFIG_BPF \
	{ \
		BPF_global_init, \
		BPF_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC | CS_MODE_BPF_EXTENDED \
				| CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_RISCV \
	{ \
		RISCV_global_init, \
		RISCV_option, \
		~(CS_MODE_RISCV32 | CS_MODE_RISCV64 | CS_MODE_RISCVC), \
	}
#define CS_ARCH_CONFIG_SH \
	{ \
		SH_global_init, \
		SH_option, \
		~(CS_MODE_SH2 | CS_MODE_SH2A | CS_MODE_SH3 | \
		  CS_MODE_SH4 | CS_MODE_SH4A | \
		  CS_MODE_SHFPU | CS_MODE_SHDSP|CS_MODE_BIG_ENDIAN), \
	}
#define CS_ARCH_CONFIG_TRICORE \
	{ \
		TRICORE_global_init, \
		TRICORE_option, \
		~(CS_MODE_TRICORE_110 | CS_MODE_TRICORE_120 | CS_MODE_TRICORE_130 \
		| CS_MODE_TRICORE_131 | CS_MODE_TRICORE_160 | CS_MODE_TRICORE_161 \
		| CS_MODE_TRICORE_162 | CS_MODE_LITTLE_ENDIAN), \
	}
#define CS_ARCH_CONFIG_ALPHA \
	{ \
		ALPHA_global_init, \
		ALPHA_option, \
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_BIG_ENDIAN), \
	}

#ifdef CAPSTONE_USE_ARCH_REGISTRATION
static cs_arch_config arch_configs[MAX_ARCH];
static uint32_t all_arch;
#else
static const cs_arch_config arch_configs[MAX_ARCH] = {
#ifdef CAPSTONE_HAS_ARM
	CS_ARCH_CONFIG_ARM,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_AARCH64
	CS_ARCH_CONFIG_AARCH64,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_MIPS
	CS_ARCH_CONFIG_MIPS,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_X86
	CS_ARCH_CONFIG_X86,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_POWERPC
	CS_ARCH_CONFIG_PPC,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_SPARC
	CS_ARCH_CONFIG_SPARC,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_SYSZ
	CS_ARCH_CONFIG_SYSZ,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_XCORE
	CS_ARCH_CONFIG_XCORE,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_M68K
	CS_ARCH_CONFIG_M68K,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_TMS320C64X
	CS_ARCH_CONFIG_TMS320C64X,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_M680X
	CS_ARCH_CONFIG_M680X,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_EVM
	CS_ARCH_CONFIG_EVM,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_MOS65XX
	CS_ARCH_CONFIG_MOS65XX,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_WASM
	CS_ARCH_CONFIG_WASM,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_BPF
	CS_ARCH_CONFIG_BPF,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_RISCV
	CS_ARCH_CONFIG_RISCV,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_SH
	CS_ARCH_CONFIG_SH,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_TRICORE
	CS_ARCH_CONFIG_TRICORE,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_ALPHA
	CS_ARCH_CONFIG_ALPHA,
#else
	{ NULL, NULL, 0 },
#endif
#ifdef CAPSTONE_HAS_HPPA
	{
		HPPA_global_init,
		HPPA_option,
		~(CS_MODE_LITTLE_ENDIAN | CS_MODE_BIG_ENDIAN | CS_MODE_HPPA_11
		| CS_MODE_HPPA_20 | CS_MODE_HPPA_20W),
	},
#else
	{ NULL, NULL, 0 },
#endif
};

// bitmask of enabled architectures
static const uint32_t all_arch = 0
#ifdef CAPSTONE_HAS_ARM
	| (1 << CS_ARCH_ARM)
#endif
#if defined(CAPSTONE_HAS_AARCH64) || defined(CAPSTONE_HAS_ARM64)
	| (1 << CS_ARCH_AARCH64)
#endif
#ifdef CAPSTONE_HAS_MIPS
	| (1 << CS_ARCH_MIPS)
#endif
#ifdef CAPSTONE_HAS_X86
	| (1 << CS_ARCH_X86)
#endif
#ifdef CAPSTONE_HAS_POWERPC
	| (1 << CS_ARCH_PPC)
#endif
#ifdef CAPSTONE_HAS_SPARC
	| (1 << CS_ARCH_SPARC)
#endif
#ifdef CAPSTONE_HAS_SYSZ
	| (1 << CS_ARCH_SYSZ)
#endif
#ifdef CAPSTONE_HAS_XCORE
	| (1 << CS_ARCH_XCORE)
#endif
#ifdef CAPSTONE_HAS_M68K
	| (1 << CS_ARCH_M68K)
#endif
#ifdef CAPSTONE_HAS_TMS320C64X
	| (1 << CS_ARCH_TMS320C64X)
#endif
#ifdef CAPSTONE_HAS_M680X
	| (1 << CS_ARCH_M680X)
#endif
#ifdef CAPSTONE_HAS_EVM
	| (1 << CS_ARCH_EVM)
#endif
#ifdef CAPSTONE_HAS_MOS65XX
	| (1 << CS_ARCH_MOS65XX)
#endif
#ifdef CAPSTONE_HAS_WASM
	| (1 << CS_ARCH_WASM)
#endif
#ifdef CAPSTONE_HAS_BPF
	| (1 << CS_ARCH_BPF)
#endif
#ifdef CAPSTONE_HAS_RISCV
	| (1 << CS_ARCH_RISCV)
#endif
#ifdef CAPSTONE_HAS_SH
	| (1 << CS_ARCH_SH)
#endif
#ifdef CAPSTONE_HAS_TRICORE
	| (1 << CS_ARCH_TRICORE)
#endif
#ifdef CAPSTONE_HAS_ALPHA
	| (1 << CS_ARCH_ALPHA)
#endif
#ifdef CAPSTONE_HAS_HPPA
	| (1 << CS_ARCH_HPPA)
#endif
;
#endif


#if defined(CAPSTONE_USE_SYS_DYN_MEM)
#if !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE)
// default
cs_malloc_t cs_mem_malloc = malloc;
cs_calloc_t cs_mem_calloc = calloc;
cs_realloc_t cs_mem_realloc = realloc;
cs_free_t cs_mem_free = free;
#if defined(_WIN32_WCE)
cs_vsnprintf_t cs_vsnprintf = _vsnprintf;
#else
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#endif  // defined(_WIN32_WCE)

#elif defined(_KERNEL_MODE)
// Windows driver
cs_malloc_t cs_mem_malloc = cs_winkernel_malloc;
cs_calloc_t cs_mem_calloc = cs_winkernel_calloc;
cs_realloc_t cs_mem_realloc = cs_winkernel_realloc;
cs_free_t cs_mem_free = cs_winkernel_free;
cs_vsnprintf_t cs_vsnprintf = cs_winkernel_vsnprintf;
#else
// OSX kernel
extern void* kern_os_malloc(size_t size);
extern void kern_os_free(void* addr);
extern void* kern_os_realloc(void* addr, size_t nsize);

static void* cs_kern_os_calloc(size_t num, size_t size)
{
	return kern_os_malloc(num * size); // malloc bzeroes the buffer
}

cs_malloc_t cs_mem_malloc = kern_os_malloc;
cs_calloc_t cs_mem_calloc = cs_kern_os_calloc;
cs_realloc_t cs_mem_realloc = kern_os_realloc;
cs_free_t cs_mem_free = kern_os_free;
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#endif  // !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE)
#else
// User-defined
cs_malloc_t cs_mem_malloc = NULL;
cs_calloc_t cs_mem_calloc = NULL;
cs_realloc_t cs_mem_realloc = NULL;
cs_free_t cs_mem_free = NULL;
cs_vsnprintf_t cs_vsnprintf = NULL;

#endif  // defined(CAPSTONE_USE_SYS_DYN_MEM)

CAPSTONE_EXPORT
unsigned int CAPSTONE_API cs_version(int *major, int *minor)
{
	if (major != NULL && minor != NULL) {
		*major = CS_API_MAJOR;
		*minor = CS_API_MINOR;
	}

	return (CS_API_MAJOR << 8) + CS_API_MINOR;
}

#define CS_ARCH_REGISTER(id) \
	cs_arch_config cfg = CS_ARCH_CONFIG_##id; \
	arch_configs[CS_ARCH_##id] = cfg; \
	all_arch |= 1 << CS_ARCH_##id

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_arm(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_ARM)
	CS_ARCH_REGISTER(ARM);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_aarch64(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_AARCH64)
	CS_ARCH_REGISTER(AARCH64);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_mips(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_MIPS)
	CS_ARCH_REGISTER(MIPS);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_x86(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_X86)
	CS_ARCH_REGISTER(X86);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_powerpc(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_POWERPC)
	CS_ARCH_REGISTER(PPC);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_sparc(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_SPARC)
	CS_ARCH_REGISTER(SPARC);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_sysz(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_SYSZ)
	CS_ARCH_REGISTER(SYSZ);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_xcore(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_XCORE)
	CS_ARCH_REGISTER(XCORE);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_m68k(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_M68K)
	CS_ARCH_REGISTER(M68K);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_tms320c64x(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_TMS320C64X)
	CS_ARCH_REGISTER(TMS320C64X);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_m680x(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_M680X)
	CS_ARCH_REGISTER(M680X);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_evm(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_EVM)
	CS_ARCH_REGISTER(EVM);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_mos65xx(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_MOS65XX)
	CS_ARCH_REGISTER(MOS65XX);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_wasm(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_WASM)
	CS_ARCH_REGISTER(WASM);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_bpf(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_BPF)
	CS_ARCH_REGISTER(BPF);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_riscv(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_RISCV)
	CS_ARCH_REGISTER(RISCV);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_sh(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_SH)
	CS_ARCH_REGISTER(SH);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_tricore(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_TRICORE)
	CS_ARCH_REGISTER(TRICORE);
#endif
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_arch_register_alpha(void)
{
#if defined(CAPSTONE_USE_ARCH_REGISTRATION) && defined(CAPSTONE_HAS_ALPHA)
	CS_ARCH_REGISTER(ALPHA);
#endif
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_support(int query)
{
	if (query == CS_ARCH_ALL)
		return all_arch ==
				    ((1 << CS_ARCH_ARM)  | (1 << CS_ARCH_AARCH64)    |
				    (1 << CS_ARCH_MIPS)  | (1 << CS_ARCH_X86)        |
				    (1 << CS_ARCH_PPC)   | (1 << CS_ARCH_SPARC)      |
				    (1 << CS_ARCH_SYSZ)  | (1 << CS_ARCH_XCORE)      |
				    (1 << CS_ARCH_M68K)  | (1 << CS_ARCH_TMS320C64X) |
				    (1 << CS_ARCH_M680X) | (1 << CS_ARCH_EVM)        |
				    (1 << CS_ARCH_RISCV) | (1 << CS_ARCH_MOS65XX)    |
				    (1 << CS_ARCH_WASM)  | (1 << CS_ARCH_BPF)        |
				    (1 << CS_ARCH_SH)    | (1 << CS_ARCH_TRICORE)    |
					(1 << CS_ARCH_ALPHA) | (1 << CS_ARCH_HPPA));

	if ((unsigned int)query < CS_ARCH_MAX)
		return all_arch & (1 << query);

	if (query == CS_SUPPORT_DIET) {
#ifdef CAPSTONE_DIET
		return true;
#else
		return false;
#endif
	}

	if (query == CS_SUPPORT_X86_REDUCE) {
#if defined(CAPSTONE_HAS_X86) && defined(CAPSTONE_X86_REDUCE)
		return true;
#else
		return false;
#endif
	}

	// unsupported query
	return false;
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_errno(csh handle)
{
	struct cs_struct *ud;
	if (!handle)
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(uintptr_t)handle;

	return ud->errnum;
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_strerror(cs_err code)
{
	switch(code) {
		default:
			return "Unknown error code";
		case CS_ERR_OK:
			return "OK (CS_ERR_OK)";
		case CS_ERR_MEM:
			return "Out of memory (CS_ERR_MEM)";
		case CS_ERR_ARCH:
			return "Invalid/unsupported architecture(CS_ERR_ARCH)";
		case CS_ERR_HANDLE:
			return "Invalid handle (CS_ERR_HANDLE)";
		case CS_ERR_CSH:
			return "Invalid csh (CS_ERR_CSH)";
		case CS_ERR_MODE:
			return "Invalid mode (CS_ERR_MODE)";
		case CS_ERR_OPTION:
			return "Invalid option (CS_ERR_OPTION)";
		case CS_ERR_DETAIL:
			return "Details are unavailable (CS_ERR_DETAIL)";
		case CS_ERR_MEMSETUP:
			return "Dynamic memory management uninitialized (CS_ERR_MEMSETUP)";
		case CS_ERR_VERSION:
			return "Different API version between core & binding (CS_ERR_VERSION)";
		case CS_ERR_DIET:
			return "Information irrelevant in diet engine (CS_ERR_DIET)";
		case CS_ERR_SKIPDATA:
			return "Information irrelevant for 'data' instruction in SKIPDATA mode (CS_ERR_SKIPDATA)";
		case CS_ERR_X86_ATT:
			return "AT&T syntax is unavailable (CS_ERR_X86_ATT)";
		case CS_ERR_X86_INTEL:
			return "INTEL syntax is unavailable (CS_ERR_X86_INTEL)";
		case CS_ERR_X86_MASM:
			return "MASM syntax is unavailable (CS_ERR_X86_MASM)";
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	cs_err err;
	struct cs_struct *ud = NULL;
	if (!cs_mem_malloc || !cs_mem_calloc || !cs_mem_realloc || !cs_mem_free || !cs_vsnprintf)
		// Error: before cs_open(), dynamic memory management must be initialized
		// with cs_option(CS_OPT_MEM)
		return CS_ERR_MEMSETUP;

	if (arch < CS_ARCH_MAX && arch_configs[arch].arch_init) {
		// verify if requested mode is valid
		if (mode & arch_configs[arch].arch_disallowed_mode_mask) {
			*handle = 0;
			return CS_ERR_MODE;
		}

		ud = cs_mem_calloc(1, sizeof(*ud));
		if (!ud) {
			// memory insufficient
			return CS_ERR_MEM;
		}

		ud->errnum = CS_ERR_OK;
		ud->arch = arch;
		ud->mode = mode;
		// by default, do not break instruction into details
		ud->detail_opt = CS_OPT_OFF;

		// default skipdata setup
		ud->skipdata_setup.mnemonic = SKIPDATA_MNEM;

		err = arch_configs[ud->arch].arch_init(ud);
		if (err) {
			cs_mem_free(ud);
			*handle = 0;
			return err;
		}

		*handle = (uintptr_t)ud;

		return CS_ERR_OK;
	} else {
		cs_mem_free(ud);
		*handle = 0;
		return CS_ERR_ARCH;
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_close(csh *handle)
{
	struct cs_struct *ud = NULL;
	struct insn_mnem *next = NULL, *tmp = NULL;

	if (*handle == 0)
		// invalid handle
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(*handle);

	if (ud->printer_info)
		cs_mem_free(ud->printer_info);

	// free the linked list of customized mnemonic
	tmp = ud->mnem_list;
	while(tmp) {
		next = tmp->next;
		cs_mem_free(tmp);
		tmp = next;
	}

	cs_mem_free(ud->insn_cache);

	memset(ud, 0, sizeof(*ud));
	cs_mem_free(ud);

	// invalidate this handle by ZERO out its value.
	// this is to make sure it is unusable after cs_close()
	*handle = 0;

	return CS_ERR_OK;
}

/// replace str1 in target with str2; target starts with str1
/// output is put into result (which is array of char with size CS_MNEMONIC_SIZE)
/// return 0 on success, -1 on failure
#ifndef CAPSTONE_DIET
static int str_replace(char *result, char *target, const char *str1, char *str2)
{
	size_t target_len = strlen(target);
	size_t str1_len = strlen(str1);
	if (target_len < str1_len) {
		return -1;
	}

	// only perform replacement if the output fits into result
	if (target_len - str1_len + strlen(str2) <= CS_MNEMONIC_SIZE - 1)  {
		// copy str2 to beginning of result
		// skip str1 - already replaced by str2
		snprintf(result, CS_MNEMONIC_SIZE, "%s%s", str2, target + str1_len);

		return 0;
	} else
		return -1;
}
#endif

/// The asm string sometimes has a leading space or tab.
/// Here we remove it.
static void fixup_asm_string(char *asm_str) {
	if (!asm_str) {
		return;
	}
	int i = 0;
	int k = 0;
	bool text_reached = (asm_str[0] != ' ' && asm_str[0] != '\t');
	while (asm_str[i]) {
		if (!text_reached && (asm_str[i] == ' ' || asm_str[i] == '\t')) {
			++i;
			text_reached = true;
			continue;
		}
		asm_str[k] = asm_str[i];
		++k, ++i;
	}
	asm_str[k] = '\0';
}

// fill insn with mnemonic & operands info
static void fill_insn(struct cs_struct *handle, cs_insn *insn, char *buffer, MCInst *mci,
		PostPrinter_t postprinter, const uint8_t *code)
{
#ifndef CAPSTONE_DIET
	char *sp, *mnem;
#endif
	fixup_asm_string(buffer);
	uint16_t copy_size = MIN(sizeof(insn->bytes), insn->size);

	// fill the instruction bytes.
	// we might skip some redundant bytes in front in the case of X86
	memcpy(insn->bytes, code + insn->size - copy_size, copy_size);
	insn->op_str[0] = '\0';
	insn->size = copy_size;

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, buffer, mci);

#ifndef CAPSTONE_DIET
	mnem = insn->mnemonic;
	// memset(mnem, 0, CS_MNEMONIC_SIZE);
	for (sp = buffer; *sp; sp++) {
		if (*sp == ' '|| *sp == '\t')
			break;
		if (*sp == '|')	// lock|rep prefix for x86
			*sp = ' ';
		// copy to @mnemonic
		*mnem = *sp;
		mnem++;
	}

	*mnem = '\0';

	// we might have customized mnemonic
	if (handle->mnem_list) {
		struct insn_mnem *tmp = handle->mnem_list;
		while(tmp) {
			if (tmp->insn.id == insn->id) {
				char str[CS_MNEMONIC_SIZE];

				if (!str_replace(str, insn->mnemonic, cs_insn_name((csh)handle, insn->id), tmp->insn.mnemonic)) {
					// copy result to mnemonic
					(void)strncpy(insn->mnemonic, str, sizeof(insn->mnemonic) - 1);
					insn->mnemonic[sizeof(insn->mnemonic) - 1] = '\0';
				}

				break;
			}
			tmp = tmp->next;
		}
	}

	// copy @op_str
	if (*sp) {
		// find the next non-space char
		sp++;
		for (; ((*sp == ' ') || (*sp == '\t')); sp++);
		strncpy(insn->op_str, sp, sizeof(insn->op_str) - 1);
		insn->op_str[sizeof(insn->op_str) - 1] = '\0';
	} else
		insn->op_str[0] = '\0';

#endif
}

// how many bytes will we skip when encountering data (CS_OPT_SKIPDATA)?
// this very much depends on instruction alignment requirement of each arch.
static uint8_t skipdata_size(cs_struct *handle)
{
	switch(handle->arch) {
		default:
			// should never reach
			return (uint8_t)-1;
		case CS_ARCH_ARM:
			// skip 2 bytes on Thumb mode.
			if (handle->mode & CS_MODE_THUMB)
				return 2;
			// otherwise, skip 4 bytes
			return 4;
		case CS_ARCH_AARCH64:
		case CS_ARCH_MIPS:
		case CS_ARCH_PPC:
		case CS_ARCH_SPARC:
			// skip 4 bytes
			return 4;
		case CS_ARCH_SYSZ:
			// SystemZ instruction's length can be 2, 4 or 6 bytes,
			// so we just skip 2 bytes
			return 2;
		case CS_ARCH_X86:
			// X86 has no restriction on instruction alignment
			return 1;
		case CS_ARCH_XCORE:
			// XCore instruction's length can be 2 or 4 bytes,
			// so we just skip 2 bytes
			return 2;
		case CS_ARCH_M68K:
			// M68K has 2 bytes instruction alignment but contain multibyte instruction so we skip 2 bytes
			return 2;
		case CS_ARCH_TMS320C64X:
			// TMS320C64x alignment is 4.
			return 4;
		case CS_ARCH_M680X:
			// M680X alignment is 1.
			return 1;
		case CS_ARCH_EVM:
			// EVM alignment is 1.
			return 1;
		case CS_ARCH_WASM:
			//WASM alignment is 1
			return 1;
		case CS_ARCH_MOS65XX:
			// MOS65XX alignment is 1.
			return 1;
		case CS_ARCH_BPF:
			// both classic and extended BPF have alignment 8.
			return 8;
		case CS_ARCH_RISCV:
			// special compress mode
			if (handle->mode & CS_MODE_RISCVC)
				return 2;
			return 4;
		case CS_ARCH_SH:
			return 2;
		case CS_ARCH_TRICORE:
			// TriCore instruction's length can be 2 or 4 bytes,
			// so we just skip 2 bytes
			return 2;
		case CS_ARCH_ALPHA:
			// Alpha alignment is 4.
			return 4;
		case CS_ARCH_HPPA:
			// Hppa alignment is 4.
			return 4;
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_option(csh ud, cs_opt_type type, size_t value)
{
	struct cs_struct *handle;
	cs_opt_mnem *opt;

	// cs_option() can be called with NULL handle just for CS_OPT_MEM
	// This is supposed to be executed before all other APIs (even cs_open())
	if (type == CS_OPT_MEM) {
		cs_opt_mem *mem = (cs_opt_mem *)value;

		cs_mem_malloc = mem->malloc;
		cs_mem_calloc = mem->calloc;
		cs_mem_realloc = mem->realloc;
		cs_mem_free = mem->free;
		cs_vsnprintf = mem->vsnprintf;

		return CS_ERR_OK;
	}

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle)
		return CS_ERR_CSH;

	switch(type) {
		default:
			break;

		case CS_OPT_UNSIGNED:
			handle->imm_unsigned = (cs_opt_value)value;
			return CS_ERR_OK;

		case CS_OPT_DETAIL:
			handle->detail_opt |= (cs_opt_value)value;
			return CS_ERR_OK;

		case CS_OPT_SKIPDATA:
			handle->skipdata = (value == CS_OPT_ON);
			if (handle->skipdata) {
				if (handle->skipdata_size == 0) {
					// set the default skipdata size
					handle->skipdata_size = skipdata_size(handle);
				}
			}
			return CS_ERR_OK;

		case CS_OPT_SKIPDATA_SETUP:
			if (value) {
				handle->skipdata_setup = *((cs_opt_skipdata *)value);
				if (handle->skipdata_setup.mnemonic == NULL) {
					handle->skipdata_setup.mnemonic = SKIPDATA_MNEM;
				}
			}
			return CS_ERR_OK;

		case CS_OPT_MNEMONIC:
			opt = (cs_opt_mnem *)value;
			if (opt->id) {
				if (opt->mnemonic) {
					struct insn_mnem *tmp;

					// add new instruction, or replace existing instruction
					// 1. find if we already had this insn in the linked list
					tmp = handle->mnem_list;
					while(tmp) {
						if (tmp->insn.id == opt->id) {
							// found this instruction, so replace its mnemonic
							(void)strncpy(tmp->insn.mnemonic, opt->mnemonic, sizeof(tmp->insn.mnemonic) - 1);
							tmp->insn.mnemonic[sizeof(tmp->insn.mnemonic) - 1] = '\0';
							break;
						}
						tmp = tmp->next;
					}

					// 2. add this instruction if we have not had it yet
					if (!tmp) {
						tmp = cs_mem_malloc(sizeof(*tmp));
						tmp->insn.id = opt->id;
						(void)strncpy(tmp->insn.mnemonic, opt->mnemonic, sizeof(tmp->insn.mnemonic) - 1);
						tmp->insn.mnemonic[sizeof(tmp->insn.mnemonic) - 1] = '\0';
						// this new instruction is heading the list
						tmp->next = handle->mnem_list;
						handle->mnem_list = tmp;
					}
					return CS_ERR_OK;
				} else {
					struct insn_mnem *prev, *tmp;

					// we want to delete an existing instruction
					// iterate the list to find the instruction to remove it
					tmp = handle->mnem_list;
					prev = tmp;
					while(tmp) {
						if (tmp->insn.id == opt->id) {
							// delete this instruction
							if (tmp == prev) {
								// head of the list
								handle->mnem_list = tmp->next;
							} else {
								prev->next = tmp->next;
							}
							cs_mem_free(tmp);
							break;
						}
						prev = tmp;
						tmp = tmp->next;
					}
				}
			}
			return CS_ERR_OK;

		case CS_OPT_MODE:
			// verify if requested mode is valid
			if (value & arch_configs[handle->arch].arch_disallowed_mode_mask) {
				return CS_ERR_OPTION;
			}
			break;
		case CS_OPT_NO_BRANCH_OFFSET:
			if (handle->PrintBranchImmNotAsAddress)
				return CS_ERR_OK;
			break;
	}

	if (!arch_configs[handle->arch].arch_option)
		return CS_ERR_ARCH;

	return arch_configs[handle->arch].arch_option(handle, type, value);
}

CAPSTONE_EXPORT
cs_buffer * CAPSTONE_API cs_buffer_new(size_t capacity) {
	cs_buffer *buffer = cs_mem_malloc(sizeof(cs_buffer));
	if (!buffer) {
		return NULL;
	}
	// NOTE: private is not used right now
	buffer->private = NULL;
	buffer->count = 0;
	buffer->capacity = capacity ? capacity : 64;
	buffer->insn = cs_mem_calloc(sizeof(cs_insn), buffer->capacity);
	if (!buffer->insn) {
		cs_mem_free(buffer);
		return NULL;
	}
	return buffer;
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_buffer_free(cs_buffer *buffer) {
	for (size_t i = 0; i < buffer->capacity; ++i) {
		// can be allocated in cs_disasm()
		if (buffer->insn[i].detail) {
			cs_mem_free(buffer->insn[i].detail);
		}
	}
	cs_mem_free(buffer->insn);
	cs_mem_free(buffer);
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_buffer_clear(cs_buffer *buffer) {
	buffer->count = 0;
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_buffer_reserve_exact(cs_buffer *buffer, size_t required) {
	cs_insn *insn;

	// free is required if user requested buffer shrink
	// details can be allocated by previous cs_disasm() calls
	if (required < buffer->capacity) {
		// set count to a required capacity because we will free
		// instruction details in a loop bellow and in case realloc() will fail
		if (required < buffer->count) {
			buffer->count = required;
		}

		for (size_t i = required; i < buffer->capacity; ++i) {
			if (buffer->insn[i].detail) {
				cs_mem_free(buffer->insn[i].detail);
			}
		}
	}

	insn = cs_mem_realloc(buffer->insn, required * sizeof(cs_insn));
	if (!insn) {
		return false;
	}

	// set to NULL all pointers in cs_insn if buffer grows in size
	if (required > buffer->capacity) {
		size_t diff = required - buffer->capacity;
		memset(&insn[buffer->capacity], 0, diff * sizeof(cs_insn));
	}

	buffer->insn = insn;
	buffer->capacity = required;

	return true;
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_buffer_reserve(cs_buffer *buffer, size_t additional) {
	size_t required = buffer->capacity + additional;
	size_t capacity = buffer->capacity * 8 / 5; // * 1.6 ~ golden ratio
	// increase capacity by 1.6 factor if the requested capacity change is too small
	if (capacity < required) {
		// use requested capacity change if it is more then 1.6 ratio increase
		capacity = required;
	}
	// make sure there is some capacity to work with
	if (capacity < 16) {
		capacity = 16;
	}
	return cs_buffer_reserve_exact(buffer, capacity);
}

// generate @op_str for data instruction of SKIPDATA
#ifndef CAPSTONE_DIET
static void skipdata_opstr(char *opstr, const uint8_t *buffer, size_t size)
{
	char *p = opstr;
	int len;
	size_t i;
	size_t available = sizeof(((cs_insn*)NULL)->op_str);

	if (!size) {
		opstr[0] = '\0';
		return;
	}

	len = cs_snprintf(p, available, "0x%02x", buffer[0]);
	p+= len;
	available -= len;

	for(i = 1; i < size; i++) {
		len = cs_snprintf(p, available, ", 0x%02x", buffer[i]);
		if (len < 0) {
			break;
		}
		if ((size_t)len > available - 1) {
			break;
		}
		p+= len;
		available -= len;
	}
}
#endif

CAPSTONE_EXPORT
size_t CAPSTONE_API cs_disasm(csh ud, const uint8_t *code, size_t code_size,
		uint64_t address, size_t count, cs_buffer *buffer)
{
	cs_struct *handle = (cs_struct *) (uintptr_t) ud;
	const uint8_t *code_org; // save all the original info of the buffer
	size_t code_size_org;
	uint64_t address_org;
	size_t next_offset;
	uint16_t insn_size;
	cs_insn *insn;
	MCInst mci;
	size_t skipdata_bytes;

	if (!handle) {
		// FIXME: how to handle this case:
		// handle->errnum = CS_ERR_HANDLE;
		return 0;
	}

	handle->errnum = CS_ERR_OK;

	cs_buffer_clear(buffer);

	// save the original offset for SKIPDATA
	code_org = code;
	code_size_org = code_size;
	address_org = address;

	for (; code_size && (count == 0 || buffer->count < count); ++buffer->count) {
		if (buffer->capacity <= buffer->count && !cs_buffer_reserve(buffer, code_size / 4)) {
			// insufficient memory
			handle->errnum = CS_ERR_MEM;
			return 0;
		}

		MCInst_Init(&mci);
		mci.csh = handle;
		mci.flat_insn = insn = &buffer->insn[buffer->count];
		// relative branches need to know the address & size of current insn
		mci.address = address;

		if (handle->detail_opt) {
			if (!insn->detail) {
				insn->detail = cs_mem_malloc(sizeof(cs_detail));
			}
		} else if (insn->detail) {
			cs_mem_free(insn->detail);
			insn->detail = NULL;
		}

		// save all the information for non-detailed mode
		insn->address = address;
#ifdef CAPSTONE_DIET
		// zero out mnemonic & op_str
		insn->mnemonic[0] = '\0';
		insn->op_str[0] = '\0';
#endif

		if (handle->disasm(ud, code, code_size, &mci, &insn_size, address,
				handle->getinsn_info))
		{
			SStream ss;
			SStream_Init(&ss);

			insn->size = insn_size;

			// map internal instruction opcode to public insn ID
			handle->insn_id(handle, insn, mci.Opcode);
			handle->printer(&mci, &ss, handle->printer_info);

			fill_insn(handle, insn, ss.buffer, &mci, handle->post_printer, code);

			// adjust for pseudo opcode (X86)
			if (handle->arch == CS_ARCH_X86 && insn->id != X86_INS_VCMP)
				insn->id += mci.popcode_adjust;

			next_offset = insn_size;
		} else	{
			// encounter a broken instruction

			// free memory of @detail pointer
			if (handle->detail_opt) {
				cs_mem_free(insn->detail);
			}
			insn->detail = NULL;

			// if there is no request to skip data, or remaining data is too small,
			// then bail out
			if (!handle->skipdata || handle->skipdata_size > code_size)
				break;

			if (handle->skipdata_setup.callback) {
				skipdata_bytes = handle->skipdata_setup.callback(code_org, code_size_org,
						(size_t)(address - address_org), handle->skipdata_setup.user_data);
				if (skipdata_bytes > code_size)
					// remaining data is not enough
					break;

				if (!skipdata_bytes)
					// user requested not to skip data, so bail out
					break;
			} else
				skipdata_bytes = handle->skipdata_size;

			// we have to skip some amount of data, depending on arch & mode
			insn->id = 0;	// invalid ID for this "data" instruction
			insn->address = address;
			insn->size = (uint16_t) skipdata_bytes;
			memcpy(insn->bytes, code, skipdata_bytes);
#ifdef CAPSTONE_DIET
			insn->mnemonic[0] = '\0';
			insn->op_str[0] = '\0';
#else
			strncpy(insn->mnemonic, handle->skipdata_setup.mnemonic,
					sizeof(insn->mnemonic) - 1);
			skipdata_opstr(insn->op_str, code, skipdata_bytes);
#endif

			next_offset = skipdata_bytes;
		}

		code += next_offset;
		code_size -= next_offset;
		address += next_offset;
	}

	return buffer->count;
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_disasm_iter(csh ud, const uint8_t **code, size_t *size,
                uint64_t *address, cs_buffer *buffer)
{
	bool ret = cs_disasm(ud, *code, *size, *address, 1, buffer);
	if (ret) {
		cs_insn *insn = &buffer->insn[0];
		*code += insn->size;
		*size -= insn->size;
		*address += insn->size;
	}
	return ret;
}

// return friendly name of register in a string
CAPSTONE_EXPORT
const char * CAPSTONE_API cs_reg_name(csh ud, unsigned int reg)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->reg_name == NULL) {
		return NULL;
	}

	return handle->reg_name(ud, reg);
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_insn_name(csh ud, unsigned int insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->insn_name == NULL) {
		return NULL;
	}

	return handle->insn_name(ud, insn);
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_group_name(csh ud, unsigned int group)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->group_name == NULL) {
		return NULL;
	}

	return handle->group_name(ud, group);
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_insn_group(csh ud, const cs_insn *insn, unsigned int group_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist8(insn->detail->groups, insn->detail->groups_count, group_id);
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_reg_read(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_read, insn->detail->regs_read_count, reg_id);
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_reg_write(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_write, insn->detail->regs_write_count, reg_id);
}

CAPSTONE_EXPORT
int CAPSTONE_API cs_op_count(csh ud, const cs_insn *insn, unsigned int op_type)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++)
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
			break;
		case CS_ARCH_AARCH64:
			for (i = 0; i < insn->detail->aarch64.op_count; i++)
				if (insn->detail->aarch64.operands[i].type == (aarch64_op_type)op_type)
					count++;
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++)
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++)
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++)
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
					count++;
			break;
		case CS_ARCH_SPARC:
			for (i = 0; i < insn->detail->sparc.op_count; i++)
				if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
					count++;
			break;
		case CS_ARCH_SYSZ:
			for (i = 0; i < insn->detail->sysz.op_count; i++)
				if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
					count++;
			break;
		case CS_ARCH_XCORE:
			for (i = 0; i < insn->detail->xcore.op_count; i++)
				if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
					count++;
			break;
		case CS_ARCH_M68K:
			for (i = 0; i < insn->detail->m68k.op_count; i++)
				if (insn->detail->m68k.operands[i].type == (m68k_op_type)op_type)
					count++;
			break;
		case CS_ARCH_TMS320C64X:
			for (i = 0; i < insn->detail->tms320c64x.op_count; i++)
				if (insn->detail->tms320c64x.operands[i].type == (tms320c64x_op_type)op_type)
					count++;
			break;
		case CS_ARCH_M680X:
			for (i = 0; i < insn->detail->m680x.op_count; i++)
				if (insn->detail->m680x.operands[i].type == (m680x_op_type)op_type)
					count++;
			break;
		case CS_ARCH_EVM:
			break;
		case CS_ARCH_MOS65XX:
			for (i = 0; i < insn->detail->mos65xx.op_count; i++)
				if (insn->detail->mos65xx.operands[i].type == (mos65xx_op_type)op_type)
					count++;
			break;
		case CS_ARCH_WASM:
			for (i = 0; i < insn->detail->wasm.op_count; i++)
				if (insn->detail->wasm.operands[i].type == (wasm_op_type)op_type)
					count++;
			break;
		case CS_ARCH_BPF:
			for (i = 0; i < insn->detail->bpf.op_count; i++)
				if (insn->detail->bpf.operands[i].type == (bpf_op_type)op_type)
					count++;
			break;
		case CS_ARCH_RISCV:
			for (i = 0; i < insn->detail->riscv.op_count; i++)
				if (insn->detail->riscv.operands[i].type == (riscv_op_type)op_type)
					count++;
			break;
		case CS_ARCH_TRICORE:
			for (i = 0; i < insn->detail->tricore.op_count; i++)
				if (insn->detail->tricore.operands[i].type == (tricore_op_type)op_type)
					count++;
			break;
		case CS_ARCH_ALPHA:
			for (i = 0; i < insn->detail->alpha.op_count; i++)
				if (insn->detail->alpha.operands[i].type == (alpha_op_type)op_type)
					count++;
			break;
		case CS_ARCH_HPPA:
			for (i = 0; i < insn->detail->hppa.op_count; i++)
				if (insn->detail->hppa.operands[i].type == (hppa_op_type)op_type)
					count++;
			break;
	}

	return count;
}

CAPSTONE_EXPORT
int CAPSTONE_API cs_op_index(csh ud, const cs_insn *insn, unsigned int op_type,
		unsigned int post)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++) {
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_AARCH64:
			for (i = 0; i < insn->detail->aarch64.op_count; i++) {
				if (insn->detail->aarch64.operands[i].type == (aarch64_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++) {
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++) {
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++) {
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_SPARC:
			for (i = 0; i < insn->detail->sparc.op_count; i++) {
				if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_SYSZ:
			for (i = 0; i < insn->detail->sysz.op_count; i++) {
				if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_XCORE:
			for (i = 0; i < insn->detail->xcore.op_count; i++) {
				if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_TRICORE:
			for (i = 0; i < insn->detail->tricore.op_count; i++) {
				if (insn->detail->tricore.operands[i].type == (tricore_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_M68K:
			for (i = 0; i < insn->detail->m68k.op_count; i++) {
				if (insn->detail->m68k.operands[i].type == (m68k_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_TMS320C64X:
			for (i = 0; i < insn->detail->tms320c64x.op_count; i++) {
				if (insn->detail->tms320c64x.operands[i].type == (tms320c64x_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_M680X:
			for (i = 0; i < insn->detail->m680x.op_count; i++) {
				if (insn->detail->m680x.operands[i].type == (m680x_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_EVM:
#if 0
			for (i = 0; i < insn->detail->evm.op_count; i++) {
				if (insn->detail->evm.operands[i].type == (evm_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
#endif
			break;
		case CS_ARCH_MOS65XX:
			for (i = 0; i < insn->detail->mos65xx.op_count; i++) {
				if (insn->detail->mos65xx.operands[i].type == (mos65xx_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_WASM:
			for (i = 0; i < insn->detail->wasm.op_count; i++) {
				if (insn->detail->wasm.operands[i].type == (wasm_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_BPF:
			for (i = 0; i < insn->detail->bpf.op_count; i++) {
				if (insn->detail->bpf.operands[i].type == (bpf_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_RISCV:
			for (i = 0; i < insn->detail->riscv.op_count; i++) {
				if (insn->detail->riscv.operands[i].type == (riscv_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_SH:
			for (i = 0; i < insn->detail->sh.op_count; i++) {
				if (insn->detail->sh.operands[i].type == (sh_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_ALPHA:
			for (i = 0; i < insn->detail->alpha.op_count; i++) {
				if (insn->detail->alpha.operands[i].type == (alpha_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_HPPA:
			for (i = 0; i < insn->detail->hppa.op_count; i++) {
				if (insn->detail->hppa.operands[i].type == (hppa_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
	}

	return -1;
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_regs_access(csh ud, const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	struct cs_struct *handle;

	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

#ifdef CAPSTONE_DIET
	// This API does not work in DIET mode
	handle->errnum = CS_ERR_DIET;
	return CS_ERR_DIET;
#else
	if (!handle->detail_opt) {
		handle->errnum = CS_ERR_DETAIL;
		return CS_ERR_DETAIL;
	}

	if (!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return CS_ERR_SKIPDATA;
	}

	if (!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return CS_ERR_DETAIL;
	}

	if (handle->reg_access) {
		handle->reg_access(insn, regs_read, regs_read_count, regs_write, regs_write_count);
	} else {
		// this arch is unsupported yet
		handle->errnum = CS_ERR_ARCH;
		return CS_ERR_ARCH;
	}

	return CS_ERR_OK;
#endif
}
