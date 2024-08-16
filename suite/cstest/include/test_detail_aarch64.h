// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_AARCH64_H
#define TEST_DETAIL_AARCH64_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
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
	tbool is_vreg;
	int vector_index;
	bool vector_index_is_set;

	tbool is_list_member;
} TestDetailAArch64Op;

static const cyaml_schema_field_t test_detail_aarch64_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64Op, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"sub_type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAArch64Op, sub_type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64Op, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64Op, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailAArch64Op, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAArch64Op, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_index", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAArch64Op, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailAArch64Op,
			mem_disp),
	CYAML_FIELD_INT("imm_range_first", CYAML_FLAG_OPTIONAL,
			TestDetailAArch64Op, imm_range_first),
	CYAML_FIELD_INT("imm_range_offset", CYAML_FLAG_OPTIONAL,
			TestDetailAArch64Op, imm_range_offset),
	CYAML_FIELD_FLOAT("fp", CYAML_FLAG_OPTIONAL, TestDetailAArch64Op, fp),
	CYAML_FIELD_UINT("sys_raw_val", CYAML_FLAG_OPTIONAL,
			 TestDetailAArch64Op, sys_raw_val),
	CYAML_FIELD_STRING_PTR(
		"shift_type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAArch64Op, shift_type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("shift_value", CYAML_FLAG_OPTIONAL,
			 TestDetailAArch64Op, shift_value),
	CYAML_FIELD_STRING_PTR("ext", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64Op, ext, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("vas", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64Op, vas, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("is_vreg", CYAML_FLAG_OPTIONAL, TestDetailAArch64Op,
			is_vreg),
	CYAML_FIELD_INT("vector_index", CYAML_FLAG_OPTIONAL,
			TestDetailAArch64Op, vector_index),
	CYAML_FIELD_BOOL("vector_index_is_set", CYAML_FLAG_OPTIONAL,
			TestDetailAArch64Op, vector_index_is_set),
	CYAML_FIELD_INT("is_list_member", CYAML_FLAG_OPTIONAL,
			TestDetailAArch64Op, is_list_member),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_aarch64_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailAArch64Op,
			    test_detail_aarch64_op_mapping_schema),
};

typedef struct {
	char *cc;
	tbool update_flags;
	tbool post_indexed;
	TestDetailAArch64Op **operands;
	uint32_t operands_count;
} TestDetailAArch64;

static const cyaml_schema_field_t test_detail_aarch64_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("cc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAArch64, cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("update_flags", CYAML_FLAG_OPTIONAL, TestDetailAArch64,
			update_flags),
	CYAML_FIELD_INT("post_indexed", CYAML_FLAG_OPTIONAL, TestDetailAArch64,
			post_indexed),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAArch64, operands, &test_detail_aarch64_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailAArch64 *test_detail_aarch64_new();
TestDetailAArch64 *test_detail_aarch64_clone(TestDetailAArch64 *detail);
void test_detail_aarch64_free(TestDetailAArch64 *detail);

TestDetailAArch64Op *test_detail_aarch64_op_new();
TestDetailAArch64Op *test_detail_aarch64_op_clone(TestDetailAArch64Op *detail);
void test_detail_aarch64_op_free(TestDetailAArch64Op *detail);

bool test_expected_aarch64(csh *handle, cs_aarch64 *actual,
			   TestDetailAArch64 *expected);

#endif // TEST_DETAIL_AARCH64_H
