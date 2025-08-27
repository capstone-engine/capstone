/* Tang Yuhang <tyh000011112222@gmail.com> 2016 */
/* pancake <pancake@nopcode.org> 2017 */

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "getopt.h"

#include <capstone/capstone.h>
#include "cstool.h"

#ifdef CAPSTONE_AARCH64_COMPAT_HEADER
#define CS_ARCH_AARCH64 CS_ARCH_ARM64
#endif

void print_string_hex(const char *comment, unsigned char *str, size_t len);

static struct {
	const char *name;
	const char *desc;
	cs_arch archs[CS_ARCH_MAX];
	cs_opt_value opt;
	cs_mode mode;
} all_opts[] = {
	// cs_opt_value only
	{ "+att",
	  "ATT syntax",
	  { CS_ARCH_X86, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_ATT,
	  0 },
	{ "+intel",
	  "Intel syntax",
	  { CS_ARCH_X86, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_INTEL,
	  0 },
	{ "+masm",
	  "Intel MASM syntax",
	  { CS_ARCH_X86, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_MASM,
	  0 },
	{ "+noregname",
	  "Number only registers",
	  { CS_ARCH_AARCH64, CS_ARCH_ARM, CS_ARCH_LOONGARCH, CS_ARCH_MIPS,
	    CS_ARCH_PPC, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_NOREGNAME,
	  0 },
	{ "+moto",
	  "Use $ as hex prefix",
	  { CS_ARCH_MOS65XX, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_MOTOROLA,
	  0 },
	{ "+regalias",
	  "Use register aliases, like r9 > sb",
	  { CS_ARCH_ARM, CS_ARCH_AARCH64, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_CS_REG_ALIAS,
	  0 },
	{ "+percentage",
	  "Adds % in front of the registers",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_PERCENT,
	  0 },
	{ "+nodollar",
	  "Removes $ in front of the registers",
	  { CS_ARCH_LOONGARCH, CS_ARCH_MIPS, CS_ARCH_MAX },
	  CS_OPT_SYNTAX_NO_DOLLAR,
	  0 },
	// cs_mode only
	{ "+nofloat",
	  "Disables floating point support",
	  { CS_ARCH_MIPS, CS_ARCH_MAX },
	  0,
	  CS_MODE_MIPS_NOFLOAT },
	{ "+ptr64",
	  "Enables 64-bit pointers support",
	  { CS_ARCH_MIPS, CS_ARCH_MAX },
	  0,
	  CS_MODE_MIPS_PTR64 },
	{ "+thumb",
	  "Enables Thumb mode for ARM.",
	  { CS_ARCH_ARM, CS_ARCH_MAX },
	  0,
	  CS_MODE_THUMB },
	{ "+m",
	  "Enables the M extension for ARM.",
	  { CS_ARCH_ARM, CS_ARCH_MAX },
	  0,
	  CS_MODE_MCLASS },
	{ "+v8",
	  "Sets the ARM version to v8+",
	  { CS_ARCH_ARM, CS_ARCH_MAX },
	  0,
	  CS_MODE_V8 },
	{ "+aix",
	  "Enables AIX OS assembly",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_AIX_OS },
	{ "+booke",
	  "Enables BOOKE extension",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_BOOKE },
	{ "+maix",
	  "Enables Modern AIX assembly",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_MODERN_AIX_AS },
	{ "+msync",
	  "Has only the msync instruction instead of sync. Implies BookE.",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_MSYNC },
	{ "+qpx",
	  "Enables QPX extension",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_QPX },
	{ "+ps",
	  "Enables PS extension",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_PS },
	{ "+spe",
	  "Enables SPE extension",
	  { CS_ARCH_PPC, CS_ARCH_MAX },
	  0,
	  CS_MODE_SPE },
	{ "+apple",
	  "Enables Apple's proprietary AArch64 instructions (AMX, MUL53, and others).",
	  { CS_ARCH_AARCH64, CS_ARCH_MAX },
	  0,
	  CS_MODE_APPLE_PROPRIETARY },
	{ "+v9",
	  "Enables Sparc v9 instruction set.",
	  { CS_ARCH_SPARC, CS_ARCH_MAX },
	  0,
	  CS_MODE_V9 },
	{ NULL }
};

static struct {
	const char *name;
	const char *desc;
	cs_arch arch;
	cs_mode mode;
} all_archs[] = {
	{ "arm", "ARM, little endian", CS_ARCH_ARM, CS_MODE_ARM },
	{ "armle", "ARM, little endian", CS_ARCH_ARM,
	  CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
	{ "armbe", "ARM, big endian", CS_ARCH_ARM,
	  CS_MODE_ARM | CS_MODE_BIG_ENDIAN },

	{ "aarch64", "AArch64", CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN },
	{ "aarch64be", "AArch64, big endian", CS_ARCH_AARCH64,
	  CS_MODE_BIG_ENDIAN },

	{ "alpha", "Alpha, little endian", CS_ARCH_ALPHA,
	  CS_MODE_LITTLE_ENDIAN },
	{ "alphabe", "Alpha, big endian", CS_ARCH_ALPHA, CS_MODE_BIG_ENDIAN },

	{ "hppa11", "HPPA V1.1, little endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_11 | CS_MODE_LITTLE_ENDIAN },
	{ "hppa11be", "HPPA V1.1, big endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_11 | CS_MODE_BIG_ENDIAN },
	{ "hppa20", "HPPA V2.0, little endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_20 | CS_MODE_LITTLE_ENDIAN },
	{ "hppa20be", "HPPA V2.0, big endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_20 | CS_MODE_BIG_ENDIAN },
	{ "hppa20w", "HPPA V2.0 wide, little endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_20W | CS_MODE_LITTLE_ENDIAN },
	{ "hppa20wbe", "HPPA V2.0 wide, big endian", CS_ARCH_HPPA,
	  CS_MODE_HPPA_20W | CS_MODE_BIG_ENDIAN },

	{ "mipsel16", "Mips 16-bit (generic), little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS16 },
	{ "mips16", "Mips 16-bit (generic)", CS_ARCH_MIPS,
	  CS_MODE_MIPS16 | CS_MODE_BIG_ENDIAN },
	{ "mipsel", "Mips 32-bit (generic), little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS32 },
	{ "mips", "Mips 32-bit (generic)", CS_ARCH_MIPS,
	  CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
	{ "mipsel64", "Mips 64-bit (generic), little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS64 },
	{ "mips64", "Mips 64-bit (generic)", CS_ARCH_MIPS,
	  CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN },
	{ "micromipsel", "MicroMips, little endian", CS_ARCH_MIPS,
	  CS_MODE_MICRO },
	{ "micromips", "MicroMips", CS_ARCH_MIPS,
	  CS_MODE_MICRO | CS_MODE_BIG_ENDIAN },
	{ "micromipselr3", "MicroMips32r3, little endian", CS_ARCH_MIPS,
	  CS_MODE_MICRO32R3 },
	{ "micromipsr3", "MicroMips32r3", CS_ARCH_MIPS,
	  CS_MODE_MICRO32R3 | CS_MODE_BIG_ENDIAN },
	{ "micromipselr6", "MicroMips32r6, little endian", CS_ARCH_MIPS,
	  CS_MODE_MICRO32R6 },
	{ "micromipsr6", "MicroMips32r6", CS_ARCH_MIPS,
	  CS_MODE_MICRO32R6 | CS_MODE_BIG_ENDIAN },
	{ "mipsel1", "Mips I ISA, little endian", CS_ARCH_MIPS, CS_MODE_MIPS1 },
	{ "mips1", "Mips I ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS1 | CS_MODE_BIG_ENDIAN },
	{ "mipsel2", "Mips II ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS2 },
	{ "mips2", "Mips II ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS2 | CS_MODE_BIG_ENDIAN },
	{ "mipsel32r2", "Mips32 r2 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R2 },
	{ "mips32r2", "Mips32 r2 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R2 | CS_MODE_BIG_ENDIAN },
	{ "mipsel32r3", "Mips32 r3 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R3 },
	{ "mips32r3", "Mips32 r3 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R3 | CS_MODE_BIG_ENDIAN },
	{ "mipsel32r5", "Mips32 r5 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R5 },
	{ "mips32r5", "Mips32 r5 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R5 | CS_MODE_BIG_ENDIAN },
	{ "mipsel32r6", "Mips32 r6 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R6 },
	{ "mips32r6", "Mips32 r6 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN },
	{ "mipsel3", "Mips III ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS3 },
	{ "mips3", "Mips III ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS3 | CS_MODE_BIG_ENDIAN },
	{ "mipsel4", "Mips IV ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS4 },
	{ "mips4", "Mips IV ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS4 | CS_MODE_BIG_ENDIAN },
	{ "mipsel5", "Mips V ISA, little endian", CS_ARCH_MIPS, CS_MODE_MIPS5 },
	{ "mips5", "Mips V ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS5 | CS_MODE_BIG_ENDIAN },
	{ "mipsel64r2", "Mips64 r2 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R2 },
	{ "mips64r2", "Mips64 r2 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R2 | CS_MODE_BIG_ENDIAN },
	{ "mipsel64r3", "Mips64 r3 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R3 },
	{ "mips64r3", "Mips64 r3 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R3 | CS_MODE_BIG_ENDIAN },
	{ "mipsel64r5", "Mips64 r5 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R5 },
	{ "mips64r5", "Mips64 r5 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R5 | CS_MODE_BIG_ENDIAN },
	{ "mipsel64r6", "Mips64 r6 ISA, little endian", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R6 },
	{ "mips64r6", "Mips64 r6 ISA", CS_ARCH_MIPS,
	  CS_MODE_MIPS64R6 | CS_MODE_BIG_ENDIAN },
	{ "octeonle", "Octeon cnMIPS, little endian", CS_ARCH_MIPS,
	  CS_MODE_OCTEON },
	{ "octeon", "Octeon cnMIPS", CS_ARCH_MIPS,
	  CS_MODE_OCTEON | CS_MODE_BIG_ENDIAN },
	{ "octeonple", "Octeon+ cnMIPS, little endian", CS_ARCH_MIPS,
	  CS_MODE_OCTEONP },
	{ "octeonp", "Octeon+ cnMIPS", CS_ARCH_MIPS,
	  CS_MODE_OCTEONP | CS_MODE_BIG_ENDIAN },
	{ "nanomips", "nanoMIPS", CS_ARCH_MIPS, CS_MODE_NANOMIPS },
	{ "nms1", "nanoMIPS Subset", CS_ARCH_MIPS, CS_MODE_NMS1 },
	{ "i7200", "nanoMIPS i7200", CS_ARCH_MIPS, CS_MODE_I7200 },

	{ "x16", "x86 16-bit mode", CS_ARCH_X86, CS_MODE_16 }, // CS_MODE_16
	{ "x32", "x86 32-bit mode", CS_ARCH_X86, CS_MODE_32 }, // CS_MODE_32
	{ "x64", "x86 64-bit mode", CS_ARCH_X86, CS_MODE_64 }, // CS_MODE_64

	{ "ppc32", "PowerPC 32-bit, little endian", CS_ARCH_PPC,
	  CS_MODE_32 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc32be", "PowerPC 32-bit, big endian", CS_ARCH_PPC,
	  CS_MODE_32 | CS_MODE_BIG_ENDIAN },
	{ "ppc64", "PowerPC 64-bit, little endian", CS_ARCH_PPC,
	  CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64be", "PowerPC 64-bit, big endian", CS_ARCH_PPC,
	  CS_MODE_64 | CS_MODE_BIG_ENDIAN },
	{ "ppc64pwr7", "PowerPC 64-bit, Power7 (ISA v2.06), little endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR7 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64bepwr7", "PowerPC 64-bit, Power7 (ISA v2.06), big endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR7 | CS_MODE_BIG_ENDIAN },
	{ "ppc64pwr8", "PowerPC 64-bit, Power8 (ISA v2.07), little endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR8 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64bepwr8", "PowerPC 64-bit, Power8 (ISA v2.07), big endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR8 | CS_MODE_BIG_ENDIAN },
	{ "ppc64pwr9", "PowerPC 64-bit, Power9 (ISA v3.0), little endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR9 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64bepwr9", "PowerPC 64-bit, Power9 (ISA v3.0), big endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR9 | CS_MODE_BIG_ENDIAN },
	{ "ppc64pwr10", "PowerPC 64-bit, Power10 (ISA v3.1), little endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR10 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64bepwr10", "PowerPC 64-bit, Power10 (ISA v3.1), big endian",
	  CS_ARCH_PPC, CS_MODE_64 | CS_MODE_PWR10 | CS_MODE_BIG_ENDIAN },
	{ "ppc64FutureISA", "PowerPC 64-bit, Future ISA, little endian",
	  CS_ARCH_PPC,
	  CS_MODE_64 | CS_MODE_PPC_ISA_FUTURE | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64beFutureISA", "PowerPC 64-bit, Future ISA, big endian",
	  CS_ARCH_PPC,
	  CS_MODE_64 | CS_MODE_PPC_ISA_FUTURE | CS_MODE_BIG_ENDIAN },

	{ "sparc", "Sparc, big endian", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN },
	{ "sparcle", "Sparc, little endian", CS_ARCH_SPARC,
	  CS_MODE_LITTLE_ENDIAN },

	{ "systemz", "systemz (s390x) - all features", CS_ARCH_SYSTEMZ,
	  CS_MODE_BIG_ENDIAN },
	{ "systemz_arch8", "(arch8/z10/generic)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH8 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch9", "(arch9/z196)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH9 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch10", "(arch10/zec12)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH10 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch11", "(arch11/z13)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH11 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch12", "(arch12/z14)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH12 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch13", "(arch13/z15)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH13 | CS_MODE_BIG_ENDIAN },
	{ "systemz_arch14", "(arch14/z16)", CS_ARCH_SYSTEMZ,
	  CS_MODE_SYSTEMZ_ARCH14 | CS_MODE_BIG_ENDIAN },

	{ "s390x", "SystemZ s390x, big endian", CS_ARCH_SYSTEMZ,
	  CS_MODE_BIG_ENDIAN },

	{ "xcore", "xcore, big endian", CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN },

	{ "m68k", "m68k + big endian", CS_ARCH_M68K, CS_MODE_BIG_ENDIAN },
	{ "m68k40", "m68k40", CS_ARCH_M68K, CS_MODE_M68K_040 },

	{ "tms320c64x", "tms320c64x, big endian", CS_ARCH_TMS320C64X,
	  CS_MODE_BIG_ENDIAN },
	{ "tms320c64xle", "tms320c64x, little endian", CS_ARCH_TMS320C64X,
	  CS_MODE_LITTLE_ENDIAN },

	{ "m6800", "m680x, M6800/2", CS_ARCH_M680X, CS_MODE_M680X_6800 },
	{ "m6801", "m680x, M6801/3", CS_ARCH_M680X, CS_MODE_M680X_6801 },
	{ "m6805", "m680x, M6805", CS_ARCH_M680X, CS_MODE_M680X_6805 },
	{ "m6808", "m680x, M68HC08", CS_ARCH_M680X, CS_MODE_M680X_6808 },
	{ "m6809", "m680x, M6809", CS_ARCH_M680X, CS_MODE_M680X_6809 },
	{ "m6811", "m680x, M68HC11", CS_ARCH_M680X, CS_MODE_M680X_6811 },
	{ "cpu12", "m680x, M68HC12/HCS12", CS_ARCH_M680X, CS_MODE_M680X_CPU12 },
	{ "hd6301", "m680x, HD6301/3", CS_ARCH_M680X, CS_MODE_M680X_6301 },
	{ "hd6309", "m680x, HD6309", CS_ARCH_M680X, CS_MODE_M680X_6309 },
	{ "hcs08", "m680x, HCS08", CS_ARCH_M680X, CS_MODE_M680X_HCS08 },

	{ "evm", "ethereum virtual machine", CS_ARCH_EVM, 0 },

	{ "wasm", "web assembly", CS_ARCH_WASM, 0 },

	{ "bpf", "Classic BPF, little endian", CS_ARCH_BPF,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC },
	{ "bpfbe", "Classic BPF, big endian", CS_ARCH_BPF,
	  CS_MODE_BIG_ENDIAN | CS_MODE_BPF_CLASSIC },
	{ "ebpf", "Extended BPF, little endian", CS_ARCH_BPF,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED },
	{ "ebpfbe", "Extended BPF, big endian", CS_ARCH_BPF,
	  CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED },

	{ "riscv32", "Risc-V 32-bit, little endian", CS_ARCH_RISCV,
	  CS_MODE_RISCV32 | CS_MODE_RISCVC },
	{ "riscv64", "Risc-V 64-bit, little endian", CS_ARCH_RISCV,
	  CS_MODE_RISCV64 | CS_MODE_RISCVC },

	{ "6502", "MOS 6502", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_6502 },
	{ "65c02", "WDC 65c02", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_65C02 },
	{ "w65c02", "WDC w65c02", CS_ARCH_MOS65XX, CS_MODE_MOS65XX_W65C02 },
	{ "65816", "WDC 65816 (long m/x)", CS_ARCH_MOS65XX,
	  CS_MODE_MOS65XX_65816_LONG_MX },

	{ "sh", "SuperH SH1", CS_ARCH_SH, CS_MODE_BIG_ENDIAN },
	{ "sh2", "SuperH SH2", CS_ARCH_SH, CS_MODE_SH2 | CS_MODE_BIG_ENDIAN },
	{ "sh2e", "SuperH SH2E", CS_ARCH_SH,
	  CS_MODE_SH2 | CS_MODE_SHFPU | CS_MODE_BIG_ENDIAN },
	{ "sh-dsp", "SuperH SH2-DSP", CS_ARCH_SH,
	  CS_MODE_SH2 | CS_MODE_SHDSP | CS_MODE_BIG_ENDIAN },
	{ "sh2a", "SuperH SH2A", CS_ARCH_SH,
	  CS_MODE_SH2A | CS_MODE_BIG_ENDIAN },
	{ "sh2a-fpu", "SuperH SH2A-FPU", CS_ARCH_SH,
	  CS_MODE_SH2A | CS_MODE_SHFPU | CS_MODE_BIG_ENDIAN },
	{ "sh3", "SuperH SH3", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH3 },
	{ "sh3be", "SuperH SH3, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH3 },
	{ "sh3e", "SuperH SH3E", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH3 | CS_MODE_SHFPU },
	{ "sh3ebe", "SuperH SH3E, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH3 | CS_MODE_SHFPU },
	{ "sh3-dsp", "SuperH SH3-DSP", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH3 | CS_MODE_SHDSP },
	{ "sh3-dspbe", "SuperH SH3-DSP, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH3 | CS_MODE_SHDSP },
	{ "sh4", "SuperH SH4", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH4 | CS_MODE_SHFPU },
	{ "sh4be", "SuperH SH4, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH4 | CS_MODE_SHFPU },
	{ "sh4a", "SuperH SH4A", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH4A | CS_MODE_SHFPU },
	{ "sh4abe", "SuperH SH4A, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH4A | CS_MODE_SHFPU },
	{ "sh4al-dsp", "SuperH SH4AL-DSP", CS_ARCH_SH,
	  CS_MODE_LITTLE_ENDIAN | CS_MODE_SH4A | CS_MODE_SHDSP |
		  CS_MODE_SHFPU },
	{ "sh4al-dspbe", "SuperH SH4AL-DSP, big endian", CS_ARCH_SH,
	  CS_MODE_BIG_ENDIAN | CS_MODE_SH4A | CS_MODE_SHDSP | CS_MODE_SHFPU },

	{ "tc110", "Tricore V1.1", CS_ARCH_TRICORE, CS_MODE_TRICORE_110 },
	{ "tc120", "Tricore V1.2", CS_ARCH_TRICORE, CS_MODE_TRICORE_120 },
	{ "tc130", "Tricore V1.3", CS_ARCH_TRICORE, CS_MODE_TRICORE_130 },
	{ "tc131", "Tricore V1.3.1", CS_ARCH_TRICORE, CS_MODE_TRICORE_131 },
	{ "tc160", "Tricore V1.6", CS_ARCH_TRICORE, CS_MODE_TRICORE_160 },
	{ "tc161", "Tricore V1.6.1", CS_ARCH_TRICORE, CS_MODE_TRICORE_161 },
	{ "tc162", "Tricore V1.6.2", CS_ARCH_TRICORE, CS_MODE_TRICORE_162 },
	{ "tc180", "Tricore V1.8.0", CS_ARCH_TRICORE, CS_MODE_TRICORE_180 },

	{ "loongarch32", "LoongArch 32-bit", CS_ARCH_LOONGARCH,
	  CS_MODE_LOONGARCH32 },
	{ "loongarch64", "LoongArch 64-bit", CS_ARCH_LOONGARCH,
	  CS_MODE_LOONGARCH64 },
	{ "esp32", "Xtensa ESP32", CS_ARCH_XTENSA, CS_MODE_XTENSA_ESP32 },
	{ "esp32s2", "Xtensa ESP32S2", CS_ARCH_XTENSA, CS_MODE_XTENSA_ESP32S2 },
	{ "esp8266", "Xtensa ESP8266", CS_ARCH_XTENSA, CS_MODE_XTENSA_ESP8266 },

	{ "arc", "ARC Little-Endian", CS_ARCH_ARC, CS_MODE_LITTLE_ENDIAN },

	{ NULL }
};

static void print_details(csh handle, cs_arch arch, cs_mode md, cs_insn *ins);

void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

// convert hexchar to hexnum
static uint8_t char_to_hexnum(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}

	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + c - 'a');
	}

	//  c >= 'A' && c <= 'F'
	return (uint8_t)(10 + c - 'A');
}

// convert user input (char[]) to uint8_t[], each element of which is
// valid hexadecimal, and return actual length of uint8_t[] in @size.
static uint8_t *preprocess(char *code, size_t *size)
{
	size_t i = 0, j = 0;
	uint8_t high, low;
	uint8_t *result;

	if (strlen(code) == 0)
		return NULL;

	result = (uint8_t *)malloc(strlen(code));
	if (result != NULL) {
		while (code[i] != '\0') {
			if (isxdigit(code[i]) && isxdigit(code[i + 1])) {
				high = 16 * char_to_hexnum(code[i]);
				low = char_to_hexnum(code[i + 1]);
				result[j] = high + low;
				i++;
				j++;
			}
			i++;
		}
		*size = j;
	}

	return result;
}

static const char *get_arch_name(cs_arch arch)
{
	switch (arch) {
	case CS_ARCH_ARM:
		return "ARM";
	case CS_ARCH_AARCH64:
		return "Arm64";
	case CS_ARCH_MIPS:
		return "Mips";
	case CS_ARCH_X86:
		return "x86";
	case CS_ARCH_PPC:
		return "PowerPC";
	case CS_ARCH_SPARC:
		return "Sparc";
	case CS_ARCH_SYSTEMZ:
		return "SystemZ";
	case CS_ARCH_XCORE:
		return "Xcore";
	case CS_ARCH_M68K:
		return "M68K";
	case CS_ARCH_TMS320C64X:
		return "TMS320C64X";
	case CS_ARCH_M680X:
		return "M680X";
	case CS_ARCH_EVM:
		return "Evm";
	case CS_ARCH_MOS65XX:
		return "MOS65XX";
	case CS_ARCH_WASM:
		return "Wasm";
	case CS_ARCH_BPF:
		return "BPF";
	case CS_ARCH_RISCV:
		return "RiscV";
	case CS_ARCH_SH:
		return "SH";
	case CS_ARCH_TRICORE:
		return "TriCore";
	case CS_ARCH_ALPHA:
		return "Alpha";
	case CS_ARCH_HPPA:
		return "HPPA";
	case CS_ARCH_LOONGARCH:
		return "LoongArch";
	case CS_ARCH_ARC:
		return "ARC";
	default:
		return NULL;
	}
}

static void usage(char *prog)
{
	int i, j;
	printf("Cstool for Capstone Disassembler Engine v%u.%u.%u\n\n",
	       CS_VERSION_MAJOR, CS_VERSION_MINOR, CS_VERSION_EXTRA);
	printf("Syntax: %s [-d|-a|-r|-s|-u|-v] <arch+opts> <assembly-hexstring> [start-address-in-hex-format]\n",
	       prog);
	printf("\nThe following <arch+opts> options are supported:\n");

	for (i = 0; all_archs[i].name; i++) {
		if (cs_support(all_archs[i].arch)) {
			printf("        %-16s %s\n", all_archs[i].name,
			       all_archs[i].desc);
		}
	}

	printf("\nArch specific options:\n");
	for (i = 0; all_opts[i].name; i++) {
		printf("        %-16s %s (only: ", all_opts[i].name,
		       all_opts[i].desc);
		for (j = 0; j < CS_ARCH_MAX; j++) {
			cs_arch arch = all_opts[i].archs[j];
			const char *name = get_arch_name(arch);
			if (!name) {
				break;
			}
			if (j > 0) {
				printf(", %s", name);
			} else {
				printf("%s", name);
			}
		}
		printf(")\n");
	}

	printf("\nExtra options:\n");
	printf("        -d show detailed information of the instructions\n");
	printf("        -r show detailed information of the real instructions (even for alias)\n");
	printf("        -a Print Capstone register alias (if any). Otherwise LLVM register names are emitted.\n");
	printf("        -s decode in SKIPDATA mode\n");
	printf("        -u show immediates as unsigned\n");
	printf("        -v show version & Capstone core build info\n\n");
}

static void print_details(csh handle, cs_arch arch, cs_mode md, cs_insn *ins)
{
	printf("\tID: %u (%s)\n", ins->id, cs_insn_name(handle, ins->id));
	if (ins->is_alias) {
		printf("\tIs alias: %" PRIu64 " (%s) ", ins->alias_id,
		       cs_insn_name(handle, ins->alias_id));
		printf("with %s operand set\n",
		       ins->usesAliasDetails ? "ALIAS" : "REAL");
	}

	switch (arch) {
	case CS_ARCH_X86:
		print_insn_detail_x86(handle, md, ins);
		break;
	case CS_ARCH_ARM:
		print_insn_detail_arm(handle, ins);
		break;
	case CS_ARCH_AARCH64:
		print_insn_detail_aarch64(handle, ins);
		break;
	case CS_ARCH_MIPS:
		print_insn_detail_mips(handle, ins);
		break;
	case CS_ARCH_PPC:
		print_insn_detail_ppc(handle, ins);
		break;
	case CS_ARCH_SPARC:
		print_insn_detail_sparc(handle, ins);
		break;
	case CS_ARCH_SYSTEMZ:
		print_insn_detail_systemz(handle, ins);
		break;
	case CS_ARCH_XCORE:
		print_insn_detail_xcore(handle, ins);
		break;
	case CS_ARCH_M68K:
		print_insn_detail_m68k(handle, ins);
		break;
	case CS_ARCH_TMS320C64X:
		print_insn_detail_tms320c64x(handle, ins);
		break;
	case CS_ARCH_M680X:
		print_insn_detail_m680x(handle, ins);
		break;
	case CS_ARCH_EVM:
		print_insn_detail_evm(handle, ins);
		break;
	case CS_ARCH_WASM:
		print_insn_detail_wasm(handle, ins);
		break;
	case CS_ARCH_MOS65XX:
		print_insn_detail_mos65xx(handle, ins);
		break;
	case CS_ARCH_BPF:
		print_insn_detail_bpf(handle, ins);
		break;
	case CS_ARCH_RISCV:
		print_insn_detail_riscv(handle, ins);
		break;
	case CS_ARCH_SH:
		print_insn_detail_sh(handle, ins);
		break;
	case CS_ARCH_TRICORE:
		print_insn_detail_tricore(handle, ins);
		break;
	case CS_ARCH_ALPHA:
		print_insn_detail_alpha(handle, ins);
		break;
	case CS_ARCH_HPPA:
		print_insn_detail_hppa(handle, ins);
		break;
	case CS_ARCH_LOONGARCH:
		print_insn_detail_loongarch(handle, ins);
		break;
	case CS_ARCH_XTENSA:
		print_insn_detail_xtensa(handle, ins);
		break;
	case CS_ARCH_ARC:
		print_insn_detail_arc(handle, ins);
		break;
	default:
		break;
	}

	if (ins->detail && ins->detail->groups_count) {
		int j;

		printf("\tGroups: ");
		for (j = 0; j < ins->detail->groups_count; j++) {
			printf("%s ",
			       cs_group_name(handle, ins->detail->groups[j]));
		}
		printf("\n");
	}

	printf("\n");
}

static cs_mode find_additional_modes(const char *input, cs_arch arch)
{
	if (!input) {
		return 0;
	}
	cs_mode mode = 0;
	int i, j;
	for (i = 0; all_opts[i].name; i++) {
		if (all_opts[i].opt || !strstr(input, all_opts[i].name)) {
			continue;
		}
		for (j = 0; j < CS_ARCH_MAX; j++) {
			if (arch == all_opts[i].archs[j]) {
				mode |= all_opts[i].mode;
				break;
			}
		}
	}
	return mode;
}

static void enable_additional_options(csh handle, const char *input,
				      cs_arch arch)
{
	if (!input) {
		return;
	}
	int i, j;
	for (i = 0; all_opts[i].name; i++) {
		if (all_opts[i].mode || !strstr(input, all_opts[i].name)) {
			continue;
		}
		for (j = 0; j < CS_ARCH_MAX; j++) {
			if (arch == all_opts[i].archs[j]) {
				cs_option(handle, CS_OPT_SYNTAX,
					  all_opts[i].opt);
				break;
			}
		}
	}
}

int main(int argc, char **argv)
{
	int i, c;
	csh handle;
	char *choosen_arch;
	uint8_t *assembly;
	size_t count, size;
	uint64_t address = 0LL;
	cs_insn *insn;
	cs_err err;
	cs_mode mode;
	cs_arch arch = CS_ARCH_ALL;
	bool detail_flag = false;
	bool unsigned_flag = false;
	bool skipdata = false;
	bool custom_reg_alias = false;
	bool set_real_detail = false;
	int args_left;

	while ((c = getopt(argc, argv, "rasudhvf")) != -1) {
		switch (c) {
		case 'a':
			custom_reg_alias = true;
			break;
		case 'r':
			set_real_detail = true;
			break;
		case 's':
			skipdata = true;
			break;
		case 'u':
			unsigned_flag = true;
			break;
		case 'd':
			detail_flag = true;
			break;
		case 'v':
			printf("cstool for Capstone Disassembler, v%u.%u.%u\n",
			       CS_VERSION_MAJOR, CS_VERSION_MINOR,
			       CS_VERSION_EXTRA);

			printf("Capstone build: ");
			if (cs_support(CS_ARCH_X86)) {
				printf("x86=1 ");
			}

			if (cs_support(CS_ARCH_ARM)) {
				printf("arm=1 ");
			}

			if (cs_support(CS_ARCH_AARCH64)) {
				printf("aarch64=1 ");
			}

			if (cs_support(CS_ARCH_MIPS)) {
				printf("mips=1 ");
			}

			if (cs_support(CS_ARCH_PPC)) {
				printf("ppc=1 ");
			}

			if (cs_support(CS_ARCH_SPARC)) {
				printf("sparc=1 ");
			}

			if (cs_support(CS_ARCH_SYSTEMZ)) {
				printf("systemz=1 ");
			}

			if (cs_support(CS_ARCH_XCORE)) {
				printf("xcore=1 ");
			}

			if (cs_support(CS_ARCH_M68K)) {
				printf("m68k=1 ");
			}

			if (cs_support(CS_ARCH_TMS320C64X)) {
				printf("tms320c64x=1 ");
			}

			if (cs_support(CS_ARCH_M680X)) {
				printf("m680x=1 ");
			}

			if (cs_support(CS_ARCH_EVM)) {
				printf("evm=1 ");
			}

			if (cs_support(CS_ARCH_WASM)) {
				printf("wasm=1 ");
			}

			if (cs_support(CS_ARCH_MOS65XX)) {
				printf("mos65xx=1 ");
			}

			if (cs_support(CS_ARCH_BPF)) {
				printf("bpf=1 ");
			}

			if (cs_support(CS_ARCH_RISCV)) {
				printf("riscv=1 ");
			}

			if (cs_support(CS_ARCH_SH)) {
				printf("sh=1 ");
			}

			if (cs_support(CS_SUPPORT_DIET)) {
				printf("diet=1 ");
			}

			if (cs_support(CS_SUPPORT_X86_REDUCE)) {
				printf("x86_reduce=1 ");
			}

			if (cs_support(CS_ARCH_TRICORE)) {
				printf("tricore=1 ");
			}

			if (cs_support(CS_ARCH_ALPHA)) {
				printf("alpha=1 ");
			}

			if (cs_support(CS_ARCH_HPPA)) {
				printf("hppa=1 ");
			}

			if (cs_support(CS_ARCH_LOONGARCH)) {
				printf("loongarch=1 ");
			}

			if (cs_support(CS_ARCH_XTENSA)) {
				printf("xtensa=1 ");
			}

			if (cs_support(CS_ARCH_ARC)) {
				printf("arc=1 ");
			}

			printf("\n");
			return 0;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	args_left = argc - optind;
	if (args_left < 2 || args_left > 3) {
		usage(argv[0]);
		return -1;
	}

	choosen_arch = argv[optind];
	assembly = preprocess(argv[optind + 1], &size);
	if (!assembly) {
		usage(argv[0]);
		return -1;
	}

	if (args_left == 3) {
		char *temp, *src = argv[optind + 2];
		address = strtoull(src, &temp, 16);
		if (temp == src || *temp != '\0' || errno == ERANGE) {
			fprintf(stderr,
				"ERROR: invalid address argument, quit!\n");
			free(assembly);
			return -2;
		}
	}

	size_t arch_len = strlen(choosen_arch);
	const char *plus = strchr(choosen_arch, '+');
	if (plus) {
		arch_len = plus - choosen_arch;
	}

	for (i = 0; all_archs[i].name; i++) {
		size_t len = strlen(all_archs[i].name);
		if (len == arch_len &&
		    !strncmp(all_archs[i].name, choosen_arch, arch_len)) {
			arch = all_archs[i].arch;
			mode = all_archs[i].mode;
			mode |= find_additional_modes(plus, arch);

			err = cs_open(all_archs[i].arch, mode, &handle);
			if (err == CS_ERR_OK) {
				enable_additional_options(handle, plus, arch);

				// turn on SKIPDATA mode
				if (skipdata) {
					cs_option(handle, CS_OPT_SKIPDATA,
						  CS_OPT_ON);
				}
			} else {
				printf("cs_open() failed with: %s\n",
				       cs_strerror(err));
			}
			break;
		}
	}

	if (arch == CS_ARCH_ALL) {
		fprintf(stderr, "ERROR: Invalid <arch+mode>: \"%s\", quit!\n",
			choosen_arch);
		usage(argv[0]);
		free(assembly);
		return -1;
	}

	if (err) {
		const char *error = cs_strerror(err);
		fprintf(stderr, "ERROR: Failed on cs_open(): %s\n", error);
		usage(argv[0]);
		free(assembly);
		return -1;
	}

	if (detail_flag) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	if (unsigned_flag) {
		cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);
	}

	if (custom_reg_alias) {
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_CS_REG_ALIAS);
	}

	if (set_real_detail) {
		cs_option(handle, CS_OPT_DETAIL,
			  (CS_OPT_DETAIL_REAL | CS_OPT_ON));
	}

	count = cs_disasm(handle, assembly, size, address, 0, &insn);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			int j;

			printf("%2" PRIx64 "  ", insn[i].address);
			for (j = 0; j < insn[i].size; j++) {
				if (j > 0)
					putchar(' ');
				printf("%02x", insn[i].bytes[j]);
			}
			// Align instruction when it varies in size.
			// ex: x86, s390x or compressed riscv
			if (arch == CS_ARCH_RISCV) {
				for (; j < 4; j++) {
					printf("   ");
				}
			} else if (arch == CS_ARCH_X86) {
				for (; j < 16; j++) {
					printf("   ");
				}
			} else if (arch == CS_ARCH_SYSTEMZ) {
				for (; j < 6; j++) {
					printf("   ");
				}
			}

			printf("  %s\t%s%s\n", insn[i].mnemonic, insn[i].op_str,
			       insn[i].illegal ? "\t; Illegal instruction" :
						 "");

			if (detail_flag) {
				print_details(handle, arch, mode, &insn[i]);
			}
		}

		cs_free(insn, count);
		free(assembly);
	} else {
		fprintf(stderr, "ERROR: invalid assembly code\n");
		cs_close(&handle);
		free(assembly);
		return (-4);
	}

	cs_close(&handle);

	return 0;
}
