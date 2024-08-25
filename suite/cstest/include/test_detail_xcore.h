// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_XCORE_H
#define TEST_DETAIL_XCORE_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	char *reg;
	int32_t imm;
	char *mem_base;
	char *mem_index;
	int32_t mem_disp;
	int32_t mem_direct;
} TestDetailXCoreOp;

static const cyaml_schema_field_t test_detail_xcore_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXCoreOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXCoreOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailXCoreOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXCoreOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_index", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailXCoreOp, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailXCoreOp,
			mem_disp),
	CYAML_FIELD_INT("mem_direct", CYAML_FLAG_OPTIONAL, TestDetailXCoreOp,
			mem_direct),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_xcore_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailXCoreOp,
			    test_detail_xcore_op_mapping_schema),
};

typedef struct {
	TestDetailXCoreOp **operands;
	uint32_t operands_count;
} TestDetailXCore;

static const cyaml_schema_field_t test_detail_xcore_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailXCore, operands, &test_detail_xcore_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailXCore *test_detail_xcore_new();
TestDetailXCore *test_detail_xcore_clone(const TestDetailXCore *detail);
void test_detail_xcore_free(TestDetailXCore *detail);

TestDetailXCoreOp *test_detail_xcore_op_new();
TestDetailXCoreOp *test_detail_xcore_op_clone(const TestDetailXCoreOp *detail);
void test_detail_xcore_op_free(TestDetailXCoreOp *detail);

bool test_expected_xcore(csh *handle, const cs_xcore *actual,
			 const TestDetailXCore *expected);

#endif // TEST_DETAIL_XCORE_H
