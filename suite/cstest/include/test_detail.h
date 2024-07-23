// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

/// @file Defines all detail structures to test against and their yaml schemas.
/// The structs currently need to be partially redefined, if they contain unions.
/// And they won't be supported until libcyaml v2:
/// https://github.com/tlsa/libcyaml/issues/186

#ifndef TEST_DETAIL_H
#define TEST_DETAIL_H

#include "test_detail_aarch64.h"
#include "test_compare.h"
#include <capstone/capstone.h>

/// The equivalent to cs_detail in capstone.h
/// but with pointers and no unions. Because cyaml does not support them.
typedef struct {
	TestDetailAArch64 *aarch64;
	// cs_x86_test x86;
	// cs_arm_test arm;
	// cs_m68k_test m68k;
	// cs_mips_test mips;
	// cs_ppc_test ppc;
	// cs_sparc_test sparc;
	// cs_sysz_test sysz;
	// cs_xcore_test xcore;
	// cs_tms320c64x_test tms320c64x;
	// cs_m680x_test m680x;
	// cs_evm_test evm;
	// cs_mos65xx_test mos65xx;
	// cs_wasm_test wasm;
	// cs_bpf_test bpf;
	// cs_riscv_test riscv;
	// cs_sh_test sh;
	// cs_tricore_test tricore;
	// cs_alpha_test alpha;
	// cs_hppa_test hppa;
	// cs_loongarch_test loongarch;

	uint16_t *regs_read;
	uint8_t regs_read_count;

	uint16_t *regs_write;
	uint8_t regs_write_count;

	uint8_t groups;
	uint8_t groups_count;

	tbool writeback;
} TestDetail;

#endif // TEST_DETAIL_H
