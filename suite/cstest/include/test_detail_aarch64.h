// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include <capstone/capstone.h>

typedef struct {
	aarch64_op_type type;
	aarch64_op_type sub_type;
	uint8_t access;

	aarch64_reg reg;
	int64_t imm;
	aarch64_reg mem_base;
	aarch64_reg mem_index;
	int32_t mem_disp;

	int8_t imm_range_first;
	int8_t imm_range_offset;
	double fp;
	uint64_t sys_raw_val;

	// aarch64_op_sme sme;
	// aarch64_op_pred pred;

	aarch64_shifter shift_type;
	unsigned int shift_value;
	aarch64_extender ext;

	int is_vreg; ///< 0 = unset; <0 = false; >0 = true
	AArch64Layout_VectorLayout vas;
	int vector_index;

	bool is_list_member; ///< 0 = unset; <0 = false; >0 = true
} TestDetailAArch64Op;

typedef struct {
	AArch64CC_CondCode cc;
	int update_flags; ///< 0 = unset; <0 = false; >0 = true
	int post_index;	  ///< 0 = unset; <0 = false; >0 = true
	int is_doing_sme; ///< 0 = unset; <0 = false; >0 = true
	TestDetailAArch64Op **operands;
	uint32_t operands_count;
} TestDetailAArch64;

TestDetailAArch64 *test_aarch64_detail_new();
TestDetailAArch64 *test_aarch64_detail_clone(TestDetailAArch64 *detail);
void test_aarch64_detail_free(TestDetailAArch64 *detail);

TestDetailAArch64Op *test_aarch64_detail_op_new();
TestDetailAArch64Op *test_aarch64_detail_op_clone(TestDetailAArch64Op *detail);
void test_aarch64_detail_op_free(TestDetailAArch64Op *detail);

bool test_expected_aarch64(cs_detail *cs_detail, TestDetailAArch64 *expected);
