// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_SYSTEMZ_H
#define TEST_DETAIL_SYSTEMZ_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
	uint8_t imm_width;
	char *mem_am;
	char *mem_base;
	char *mem_index;
	int64_t mem_disp;
	uint64_t mem_length;
} TestDetailSystemZOp;

static const cyaml_schema_field_t test_detail_systemz_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSystemZOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSystemZOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSystemZOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailSystemZOp, imm),
	CYAML_FIELD_UINT("imm_width", CYAML_FLAG_OPTIONAL, TestDetailSystemZOp,
			imm_width),
	CYAML_FIELD_STRING_PTR(
		"mem_am", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSystemZOp, mem_am, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSystemZOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_index", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSystemZOp, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailSystemZOp,
			mem_disp),
	CYAML_FIELD_INT("mem_length", CYAML_FLAG_OPTIONAL, TestDetailSystemZOp,
			mem_length),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_systemz_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailSystemZOp,
			    test_detail_systemz_op_mapping_schema),
};

typedef struct {
	char *format;
	TestDetailSystemZOp **operands;
	uint32_t operands_count;
} TestDetailSystemZ;

static const cyaml_schema_field_t test_detail_systemz_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"format", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSystemZ, format, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSystemZ, operands, &test_detail_systemz_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailSystemZ *test_detail_systemz_new();
TestDetailSystemZ *test_detail_systemz_clone(const TestDetailSystemZ *detail);
void test_detail_systemz_free(TestDetailSystemZ *detail);

TestDetailSystemZOp *test_detail_systemz_op_new();
TestDetailSystemZOp *
test_detail_systemz_op_clone(const TestDetailSystemZOp *detail);
void test_detail_systemz_op_free(TestDetailSystemZOp *detail);

bool test_expected_systemz(csh *handle, const cs_systemz *actual,
			   const TestDetailSystemZ *expected);

#endif // TEST_DETAIL_SYSTEMZ_H
