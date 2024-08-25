// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_SH_H
#define TEST_DETAIL_SH_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	char *reg;
	uint64_t imm;
	char *mem_reg;
	char *mem_address;
	int32_t mem_disp;
} TestDetailSHOp;

static const cyaml_schema_field_t test_detail_sh_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSHOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSHOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailSHOp, imm),
	CYAML_FIELD_STRING_PTR("mem_reg",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSHOp, mem_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_address",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailSHOp, mem_address, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailSHOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_sh_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailSHOp,
			    test_detail_sh_op_mapping_schema),
};

typedef struct {
	TestDetailSHOp **operands;
	uint32_t operands_count;
} TestDetailSH;

static const cyaml_schema_field_t test_detail_sh_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailSH, operands, &test_detail_sh_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailSH *test_detail_sh_new();
TestDetailSH *test_detail_sh_clone(const TestDetailSH *detail);
void test_detail_sh_free(TestDetailSH *detail);

TestDetailSHOp *test_detail_sh_op_new();
TestDetailSHOp *test_detail_sh_op_clone(const TestDetailSHOp *detail);
void test_detail_sh_op_free(TestDetailSHOp *detail);

bool test_expected_sh(csh *handle, const cs_sh *actual,
		      const TestDetailSH *expected);

#endif // TEST_DETAIL_SH_H
