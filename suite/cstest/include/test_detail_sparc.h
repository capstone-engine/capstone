// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_SPARC_H
#define TEST_DETAIL_SPARC_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	char *reg;
	int64_t imm;
	char *mem_base;
	char *mem_index;
	int32_t mem_disp;
} TestDetailSparcOp;

static const cyaml_schema_field_t test_detail_sparc_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSparcOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSparcOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailSparcOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSparcOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_index", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSparcOp, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailSparcOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_sparc_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailSparcOp,
			    test_detail_sparc_op_mapping_schema),
};

typedef struct {
	char *cc;
	char *hint;
	TestDetailSparcOp **operands;
	uint32_t operands_count;
} TestDetailSparc;

static const cyaml_schema_field_t test_detail_sparc_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("cc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSparc, cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("hint", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSparc, hint, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSparc, operands, &test_detail_sparc_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailSparc *test_detail_sparc_new();
TestDetailSparc *test_detail_sparc_clone(const TestDetailSparc *detail);
void test_detail_sparc_free(TestDetailSparc *detail);

TestDetailSparcOp *test_detail_sparc_op_new();
TestDetailSparcOp *test_detail_sparc_op_clone(const TestDetailSparcOp *detail);
void test_detail_sparc_op_free(TestDetailSparcOp *detail);

bool test_expected_sparc(csh *handle, const cs_sparc *actual,
			 const TestDetailSparc *expected);

#endif // TEST_DETAIL_SPARC_H
