// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_HPPA_H
#define TEST_DETAIL_HPPA_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
	char *mem_base;
	char *mem_space;
	char *mem_base_access;
} TestDetailHPPAOp;

static const cyaml_schema_field_t test_detail_hppa_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailHPPAOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailHPPAOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailHPPAOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailHPPAOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailHPPAOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_space",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailHPPAOp, mem_space, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_base_access", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailHPPAOp, mem_base_access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_hppa_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailHPPAOp,
			    test_detail_hppa_op_mapping_schema),
};

typedef struct {
	TestDetailHPPAOp **operands;
	uint32_t operands_count;
} TestDetailHPPA;

static const cyaml_schema_field_t test_detail_hppa_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailHPPA, operands, &test_detail_hppa_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailHPPA *test_detail_hppa_new();
TestDetailHPPA *test_detail_hppa_clone(const TestDetailHPPA *detail);
void test_detail_hppa_free(TestDetailHPPA *detail);

TestDetailHPPAOp *test_detail_hppa_op_new();
TestDetailHPPAOp *test_detail_hppa_op_clone(const TestDetailHPPAOp *detail);
void test_detail_hppa_op_free(TestDetailHPPAOp *detail);

bool test_expected_hppa(csh *handle, const cs_hppa *actual,
			const TestDetailHPPA *expected);

#endif // TEST_DETAIL_HPPA_H
