// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

/// @file Defines all detail structures to test against and their yaml schemas.
/// The structs currently need to be partially redefined, if they contain unions.
/// And they won't be supported until libcyaml v2:
/// https://github.com/tlsa/libcyaml/issues/186

#ifndef TEST_DETAIL_H
#define TEST_DETAIL_H

#include "test_detail_aarch64.h"
#include "test_detail_arm.h"
#include "test_detail_ppc.h"
#include "test_detail_riscv.h"
#include "test_detail_tricore.h"
#include "test_detail_systemz.h"
#include "test_detail_sh.h"
#include "test_detail_sparc.h"
#include "test_detail_alpha.h"
#include "test_detail_bpf.h"
#include "test_detail_hppa.h"
#include "test_detail_xcore.h"
#include "test_detail_mips.h"
#include "test_detail_riscv.h"
#include "test_detail_m680x.h"
#include "test_detail_tms320c64x.h"
#include "test_compare.h"
#include <capstone/capstone.h>
#include <cyaml/cyaml.h>

/// The equivalent to cs_detail in capstone.h
/// but with pointers and no unions. Because cyaml does not support them.
typedef struct {
	TestDetailAArch64 *aarch64;
	TestDetailARM *arm;
	TestDetailPPC *ppc;
	TestDetailTriCore *tricore;
	TestDetailAlpha *alpha;
	TestDetailHPPA *hppa;
	TestDetailBPF *bpf;
	TestDetailSystemZ *systemz;
	TestDetailSparc *sparc;
	TestDetailXCore *xcore;
	TestDetailSH *sh;
	TestDetailMips *mips;
	TestDetailRISCV *riscv;
	TestDetailM680x *m680x;
	TestDetailTMS320c64x *tms320c64x;
	// cs_x86_test x86;
	// cs_m68k_test m68k;
	// cs_tms320c64x_test tms320c64x;
	// cs_evm_test evm;
	// cs_mos65xx_test mos65xx;
	// cs_wasm_test wasm;
	// cs_loongarch_test loongarch;

	char **regs_read;
	uint8_t regs_read_count;

	char **regs_write;
	uint8_t regs_write_count;

	char **groups;
	uint8_t groups_count;

	tbool writeback;
} TestDetail;

static const cyaml_schema_value_t reg_group_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_mapping_schema[] = {
	CYAML_FIELD_MAPPING_PTR(
		"aarch64", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		aarch64, test_detail_aarch64_mapping_schema),
	CYAML_FIELD_MAPPING_PTR("arm", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
				TestDetail, arm,
				test_detail_arm_mapping_schema),
	CYAML_FIELD_MAPPING_PTR("ppc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
				TestDetail, ppc,
				test_detail_ppc_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"tricore", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		tricore, test_detail_tricore_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"alpha", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		alpha, test_detail_alpha_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"hppa", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		hppa, test_detail_hppa_mapping_schema),
	CYAML_FIELD_MAPPING_PTR("bpf", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
				TestDetail, bpf,
				test_detail_bpf_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"systemz", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		systemz, test_detail_systemz_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"sparc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		sparc, test_detail_sparc_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"xcore", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		xcore, test_detail_xcore_mapping_schema),
	CYAML_FIELD_MAPPING_PTR("sh", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
				TestDetail, sh, test_detail_sh_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"mips", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		mips, test_detail_mips_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"riscv", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		riscv, test_detail_riscv_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"m680x", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestDetail,
		m680x, test_detail_m680x_mapping_schema),
	CYAML_FIELD_MAPPING_PTR(
		"tms320c64x", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetail, tms320c64x, test_detail_tms320c64x_mapping_schema),
	CYAML_FIELD_SEQUENCE("regs_read",
			     CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetail, regs_read, &reg_group_schema, 0, 255),
	CYAML_FIELD_SEQUENCE("regs_write",
			     CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetail, regs_write, &reg_group_schema, 0, 255),
	CYAML_FIELD_SEQUENCE("groups", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetail, groups, &reg_group_schema, 0, 255),
	CYAML_FIELD_INT("writeback", CYAML_FLAG_OPTIONAL, TestDetail,
			writeback),
	CYAML_FIELD_END
};

TestDetail *test_detail_new();
TestDetail *test_detail_clone(TestDetail *detail);
void test_detail_free(TestDetail *detail);

bool test_expected_detail(csh *handle, const cs_insn *insn,
			  TestDetail *expected);

#endif // TEST_DETAIL_H
