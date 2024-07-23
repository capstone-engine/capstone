// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *sub_type;
	char *access;

	char *reg;
	int64_t imm;
	char *mem_base;
	char *mem_index;
	int32_t mem_disp;

	int8_t imm_range_first;
	int8_t imm_range_offset;
	double fp;
	uint64_t sys_raw_val;

	// aarch64_op_sme sme;
	// aarch64_op_pred pred;

	char *shift_type;
	uint32_t shift_value;
	char *ext;

	char *vas;
	int is_vreg; ///< 0 = unset; <0 = false; >0 = true
	int vector_index;

	int is_list_member; ///< 0 = unset; <0 = false; >0 = true
} TestDetailAArch64Op;

typedef struct {
	char *cc;
	int update_flags; ///< 0 = unset; <0 = false; >0 = true
	int post_index;	  ///< 0 = unset; <0 = false; >0 = true
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
