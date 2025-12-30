// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_ALPHA_H
#define TEST_DETAIL_ALPHA_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
} TestDetailAlphaOp;

static const cyaml_schema_field_t test_detail_alpha_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAlphaOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAlphaOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailAlphaOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailAlphaOp, imm),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_alpha_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailAlphaOp,
			    test_detail_alpha_op_mapping_schema),
};

typedef struct {
	TestDetailAlphaOp **operands;
	uint32_t operands_count;
} TestDetailAlpha;

static const cyaml_schema_field_t test_detail_alpha_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailAlpha, operands, &test_detail_alpha_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailAlpha *test_detail_alpha_new();
TestDetailAlpha *test_detail_alpha_clone(const TestDetailAlpha *detail);
void test_detail_alpha_free(TestDetailAlpha *detail);

TestDetailAlphaOp *test_detail_alpha_op_new();
TestDetailAlphaOp *test_detail_alpha_op_clone(const TestDetailAlphaOp *detail);
void test_detail_alpha_op_free(TestDetailAlphaOp *detail);

bool test_expected_alpha(csh *handle, const cs_alpha *actual,
			 const TestDetailAlpha *expected);

#endif // TEST_DETAIL_ALPHA_H
