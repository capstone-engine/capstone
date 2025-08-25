// Copyright © 2024 Sibirtsev Dmitry <sibirtsevdl@gmail.com>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_ARC_H
#define TEST_DETAIL_ARC_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
} TestDetailARCOp;

static const cyaml_schema_field_t test_detail_arc_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARCOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARCOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARCOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailARCOp, imm),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_arc_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailARCOp,
			    test_detail_arc_op_mapping_schema),
};

typedef struct {
	TestDetailARCOp **operands;
	uint32_t operands_count;
} TestDetailARC;

static const cyaml_schema_field_t test_detail_arc_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailARC, operands, &test_detail_arc_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailARC *test_detail_arc_new();
TestDetailARC *test_detail_arc_clone(const TestDetailARC *detail);
void test_detail_arc_free(TestDetailARC *detail);

TestDetailARCOp *test_detail_arc_op_new();
TestDetailARCOp *test_detail_arc_op_clone(const TestDetailARCOp *detail);
void test_detail_arc_op_free(TestDetailARCOp *detail);

bool test_expected_arc(csh *handle, const cs_arc *actual,
		       const TestDetailARC *expected);

#endif // TEST_DETAIL_ARC_H
