// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_MAPPING_H
#define TEST_MAPPING_H

#include <capstone/capstone.h>

/// Maps a string to the CS_ARCH enum
typedef struct {
  const char *str;
  cs_arch arch;
} TestArchMapEntry;

/// Maps a string to the CS_MODE enum
typedef struct {
  const char *str;
  cs_mode mode;
} TestModeMapEntry;

/// Maps a string to an option
typedef struct {
  const char *str;
  cs_opt opt;
} TestOptionMapEntry;

static const TestArchMapEntry test_arch_map[] = {
	{ .str = "CS_ARCH_ARM", .arch = CS_ARCH_ARM },
	{ .str = "CS_ARCH_AARCH64", .arch = CS_ARCH_AARCH64 },
	{ .str = "CS_ARCH_MIPS", .arch = CS_ARCH_MIPS },	
	{ .str = "CS_ARCH_X86", .arch = CS_ARCH_X86 },	
	{ .str = "CS_ARCH_PPC", .arch = CS_ARCH_PPC },	
	{ .str = "CS_ARCH_SPARC", .arch = CS_ARCH_SPARC },	
	{ .str = "CS_ARCH_SYSZ", .arch = CS_ARCH_SYSZ },	
	{ .str = "CS_ARCH_XCORE", .arch = CS_ARCH_XCORE },	
	{ .str = "CS_ARCH_M68K", .arch = CS_ARCH_M68K },	
	{ .str = "CS_ARCH_TMS320C64X", .arch = CS_ARCH_TMS320C64X },
	{ .str = "CS_ARCH_M680X", .arch = CS_ARCH_M680X },	
	{ .str = "CS_ARCH_EVM", .arch = CS_ARCH_EVM },	
	{ .str = "CS_ARCH_MOS65XX", .arch = CS_ARCH_MOS65XX },
	{ .str = "CS_ARCH_WASM", .arch = CS_ARCH_WASM },	
	{ .str = "CS_ARCH_BPF", .arch = CS_ARCH_BPF },	
	{ .str = "CS_ARCH_RISCV", .arch = CS_ARCH_RISCV },
	{ .str = "CS_ARCH_SH", .arch = CS_ARCH_SH },
	{ .str = "CS_ARCH_TRICORE", .arch = CS_ARCH_TRICORE },
	{ .str = "CS_ARCH_ALPHA", .arch = CS_ARCH_ALPHA },	
	{ .str = "CS_ARCH_HPPA", .arch = CS_ARCH_HPPA },	
	{ .str = "CS_ARCH_LOONGARCH", .arch = CS_ARCH_LOONGARCH },
	{ .str = "arm", .arch = CS_ARCH_ARM },
	{ .str = "aarch64", .arch = CS_ARCH_AARCH64 },
	{ .str = "mips", .arch = CS_ARCH_MIPS },	
	{ .str = "x86", .arch = CS_ARCH_X86 },	
	{ .str = "ppc", .arch = CS_ARCH_PPC },	
	{ .str = "sparc", .arch = CS_ARCH_SPARC },	
	{ .str = "sysz", .arch = CS_ARCH_SYSZ },	
	{ .str = "xcore", .arch = CS_ARCH_XCORE },	
	{ .str = "m68k", .arch = CS_ARCH_M68K },	
	{ .str = "tms320c64x", .arch = CS_ARCH_TMS320C64X },
	{ .str = "m680x", .arch = CS_ARCH_M680X },	
	{ .str = "evm", .arch = CS_ARCH_EVM },	
	{ .str = "mos65xx", .arch = CS_ARCH_MOS65XX },
	{ .str = "wasm", .arch = CS_ARCH_WASM },	
	{ .str = "bpf", .arch = CS_ARCH_BPF },	
	{ .str = "riscv", .arch = CS_ARCH_RISCV },
	{ .str = "sh", .arch = CS_ARCH_SH },
	{ .str = "tricore", .arch = CS_ARCH_TRICORE },
	{ .str = "alpha", .arch = CS_ARCH_ALPHA },	
	{ .str = "hppa", .arch = CS_ARCH_HPPA },	
	{ .str = "loongarch", .arch = CS_ARCH_LOONGARCH },
	{ .str = "AArch64", .arch = CS_ARCH_AARCH64 },
};

static const TestModeMapEntry test_mode_map[] = {
	{ .str = "CS_MODE_LITTLE_ENDIAN", .mode = CS_MODE_LITTLE_ENDIAN },
	{ .str = "CS_MODE_ARM", .mode = CS_MODE_ARM },
	{ .str = "CS_MODE_16", .mode = CS_MODE_16 },
	{ .str = "CS_MODE_32", .mode = CS_MODE_32 },
	{ .str = "CS_MODE_64", .mode = CS_MODE_64 },
	{ .str = "CS_MODE_THUMB", .mode = CS_MODE_THUMB },
	{ .str = "CS_MODE_MCLASS", .mode = CS_MODE_MCLASS },
	{ .str = "CS_MODE_V8", .mode = CS_MODE_V8 },
	{ .str = "CS_MODE_MICRO", .mode = CS_MODE_MICRO },
	{ .str = "CS_MODE_MIPS3", .mode = CS_MODE_MIPS3 },
	{ .str = "CS_MODE_MIPS32R6", .mode = CS_MODE_MIPS32R6 },
	{ .str = "CS_MODE_MIPS2", .mode = CS_MODE_MIPS2 },
	{ .str = "CS_MODE_V9", .mode = CS_MODE_V9 },
	{ .str = "CS_MODE_QPX", .mode = CS_MODE_QPX },
	{ .str = "CS_MODE_SPE", .mode = CS_MODE_SPE },
	{ .str = "CS_MODE_BOOKE", .mode = CS_MODE_BOOKE },
	{ .str = "CS_MODE_PS", .mode = CS_MODE_PS },
	{ .str = "CS_MODE_M68K_000", .mode = CS_MODE_M68K_000 },
	{ .str = "CS_MODE_M68K_010", .mode = CS_MODE_M68K_010 },
	{ .str = "CS_MODE_M68K_020", .mode = CS_MODE_M68K_020 },
	{ .str = "CS_MODE_M68K_030", .mode = CS_MODE_M68K_030 },
	{ .str = "CS_MODE_M68K_040", .mode = CS_MODE_M68K_040 },
	{ .str = "CS_MODE_M68K_060", .mode = CS_MODE_M68K_060 },
	{ .str = "CS_MODE_BIG_ENDIAN", .mode = CS_MODE_BIG_ENDIAN },
	{ .str = "CS_MODE_MIPS32", .mode = CS_MODE_MIPS32 },
	{ .str = "CS_MODE_MIPS64", .mode = CS_MODE_MIPS64 },
	{ .str = "CS_MODE_M680X_6301", .mode = CS_MODE_M680X_6301 },
	{ .str = "CS_MODE_M680X_6309", .mode = CS_MODE_M680X_6309 },
	{ .str = "CS_MODE_M680X_6800", .mode = CS_MODE_M680X_6800 },
	{ .str = "CS_MODE_M680X_6801", .mode = CS_MODE_M680X_6801 },
	{ .str = "CS_MODE_M680X_6805", .mode = CS_MODE_M680X_6805 },
	{ .str = "CS_MODE_M680X_6808", .mode = CS_MODE_M680X_6808 },
	{ .str = "CS_MODE_M680X_6809", .mode = CS_MODE_M680X_6809 },
	{ .str = "CS_MODE_M680X_6811", .mode = CS_MODE_M680X_6811 },
	{ .str = "CS_MODE_M680X_CPU12", .mode = CS_MODE_M680X_CPU12 },
	{ .str = "CS_MODE_M680X_HCS08", .mode = CS_MODE_M680X_HCS08 },
	{ .str = "CS_MODE_BPF_CLASSIC", .mode = CS_MODE_BPF_CLASSIC },
	{ .str = "CS_MODE_BPF_EXTENDED", .mode = CS_MODE_BPF_EXTENDED },
	{ .str = "CS_MODE_RISCV32", .mode = CS_MODE_RISCV32  },
	{ .str = "CS_MODE_RISCV64", .mode = CS_MODE_RISCV64  },
	{ .str = "CS_MODE_RISCVC", .mode = CS_MODE_RISCVC   },
	{ .str = "CS_MODE_MOS65XX_6502", .mode = CS_MODE_MOS65XX_6502 },
	{ .str = "CS_MODE_MOS65XX_65C02", .mode = CS_MODE_MOS65XX_65C02 },
	{ .str = "CS_MODE_MOS65XX_W65C02", .mode = CS_MODE_MOS65XX_W65C02 },
	{ .str = "CS_MODE_MOS65XX_65816", .mode = CS_MODE_MOS65XX_65816 },
	{ .str = "CS_MODE_MOS65XX_65816_LONG_M", .mode = CS_MODE_MOS65XX_65816_LONG_M },
	{ .str = "CS_MODE_MOS65XX_65816_LONG_X", .mode = CS_MODE_MOS65XX_65816_LONG_X },
	{ .str = "CS_MODE_MOS65XX_65816_LONG_MX", .mode =  CS_MODE_MOS65XX_65816_LONG_M | CS_MODE_MOS65XX_65816_LONG_X },
	{ .str = "CS_MODE_SH2", .mode = CS_MODE_SH2 },
	{ .str = "CS_MODE_SH2A", .mode = CS_MODE_SH2A },
	{ .str = "CS_MODE_SH3", .mode = CS_MODE_SH3 },
	{ .str = "CS_MODE_SH4", .mode = CS_MODE_SH4 },
	{ .str = "CS_MODE_SH4A", .mode = CS_MODE_SH4A },
	{ .str = "CS_MODE_SHFPU", .mode = CS_MODE_SHFPU },
	{ .str = "CS_MODE_SHDSP", .mode = CS_MODE_SHDSP },
	{ .str = "CS_MODE_TRICORE_110", .mode = CS_MODE_TRICORE_110 },
	{ .str = "CS_MODE_TRICORE_120", .mode = CS_MODE_TRICORE_120 },
	{ .str = "CS_MODE_TRICORE_130", .mode = CS_MODE_TRICORE_130 },
	{ .str = "CS_MODE_TRICORE_131", .mode = CS_MODE_TRICORE_131 },
	{ .str = "CS_MODE_TRICORE_160", .mode = CS_MODE_TRICORE_160 },
	{ .str = "CS_MODE_TRICORE_161", .mode = CS_MODE_TRICORE_161 },
	{ .str = "CS_MODE_TRICORE_162", .mode = CS_MODE_TRICORE_162 },
	{ .str = "CS_MODE_HPPA_11", .mode = CS_MODE_HPPA_11 },
	{ .str = "CS_MODE_HPPA_20", .mode = CS_MODE_HPPA_20 },
	{ .str = "CS_MODE_HPPA_20W", .mode = CS_MODE_HPPA_20W },
	{ .str = "CS_MODE_LOONGARCH32", .mode = CS_MODE_LOONGARCH32  },
	{ .str = "CS_MODE_LOONGARCH64", .mode = CS_MODE_LOONGARCH64  },
};

static const TestOptionMapEntry test_option_map[] = {
	{ .str = "CS_OPT_DETAIL", .opt = { .type = CS_OPT_DETAIL, .val = CS_OPT_ON } },
	{ .str = "CS_OPT_DETAIL_REAL", .opt = { .type = CS_OPT_DETAIL, .val = CS_OPT_DETAIL_REAL | CS_OPT_ON } },
	{ .str = "CS_OPT_SKIPDATA", .opt = { .type = CS_OPT_SKIPDATA, .val = CS_OPT_ON } },
	{ .str = "CS_OPT_UNSIGNED", .opt = { .type = CS_OPT_UNSIGNED, .val = CS_OPT_ON } },
	{ .str = "CS_OPT_NO_BRANCH_OFFSET", .opt = { .type = CS_OPT_NO_BRANCH_OFFSET, .val = CS_OPT_ON } },
	{ .str = "CS_OPT_SYNTAX_DEFAULT", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_DEFAULT } },
	{ .str = "CS_OPT_SYNTAX_INTEL", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_INTEL } },
	{ .str = "CS_OPT_SYNTAX_ATT", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_ATT } },
	{ .str = "CS_OPT_SYNTAX_NOREGNAME", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_NOREGNAME } },
	{ .str = "CS_OPT_SYNTAX_MASM", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_MASM } },
	{ .str = "CS_OPT_SYNTAX_MOTOROLA", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_MOTOROLA } },
	{ .str = "CS_OPT_SYNTAX_CS_REG_ALIAS", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_CS_REG_ALIAS } },
	{ .str = "CS_OPT_SYNTAX_PERCENT", .opt = { .type = CS_OPT_SYNTAX, .val = CS_OPT_SYNTAX_PERCENT } },
};

#endif // TEST_MAPPING_H
