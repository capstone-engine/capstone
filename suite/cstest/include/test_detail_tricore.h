// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_TRICORE_H
#define TEST_DETAIL_TRICORE_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
	char *mem_base;
	int64_t mem_disp;
} TestDetailTriCoreOp;

static const cyaml_schema_field_t test_detail_tricore_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailTriCoreOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailTriCoreOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailTriCoreOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailTriCoreOp, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTriCoreOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailTriCoreOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_tricore_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailTriCoreOp,
			    test_detail_tricore_op_mapping_schema),
};

typedef struct {
	tbool update_flags;
	TestDetailTriCoreOp **operands;
	uint32_t operands_count;
} TestDetailTriCore;

static const cyaml_schema_field_t test_detail_tricore_mapping_schema[] = {
	CYAML_FIELD_INT("update_flags", CYAML_FLAG_OPTIONAL, TestDetailTriCore,
			update_flags),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTriCore, operands, &test_detail_tricore_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailTriCore *test_detail_tricore_new();
TestDetailTriCore *test_detail_tricore_clone(const TestDetailTriCore *detail);
void test_detail_tricore_free(TestDetailTriCore *detail);

TestDetailTriCoreOp *test_detail_tricore_op_new();
TestDetailTriCoreOp *
test_detail_tricore_op_clone(const TestDetailTriCoreOp *detail);
void test_detail_tricore_op_free(TestDetailTriCoreOp *detail);

bool test_expected_tricore(csh *handle, const cs_tricore *actual,
			   const TestDetailTriCore *expected);

#endif // TEST_DETAIL_TRICORE_H
