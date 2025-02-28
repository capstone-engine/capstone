// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_MIPS_H
#define TEST_DETAIL_MIPS_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;
	char *reg;
	uint64_t imm;
	char *mem_base;
	int64_t mem_disp;
} TestDetailMipsOp;

static const cyaml_schema_field_t test_detail_mips_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMipsOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"access", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailMipsOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMipsOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailMipsOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMipsOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailMipsOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_mips_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailMipsOp,
			    test_detail_mips_op_mapping_schema),
};

typedef struct {
	TestDetailMipsOp **operands;
	uint32_t operands_count;
} TestDetailMips;

static const cyaml_schema_field_t test_detail_mips_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailMips, operands, &test_detail_mips_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailMips *test_detail_mips_new();
TestDetailMips *test_detail_mips_clone(const TestDetailMips *detail);
void test_detail_mips_free(TestDetailMips *detail);

TestDetailMipsOp *test_detail_mips_op_new();
TestDetailMipsOp *test_detail_mips_op_clone(const TestDetailMipsOp *detail);
void test_detail_mips_op_free(TestDetailMipsOp *detail);

bool test_expected_mips(csh *handle, const cs_mips *actual,
			const TestDetailMips *expected);

#endif // TEST_DETAIL_MIPS_H
