// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_RISCV_H
#define TEST_DETAIL_RISCV_H

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
} TestDetailRISCVOp;

static const cyaml_schema_field_t test_detail_riscv_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailRISCVOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailRISCVOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailRISCVOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailRISCVOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailRISCVOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailRISCVOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_riscv_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailRISCVOp,
			    test_detail_riscv_op_mapping_schema),
};

typedef struct {
	TestDetailRISCVOp **operands;
	uint32_t operands_count;
} TestDetailRISCV;

static const cyaml_schema_field_t test_detail_riscv_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailRISCV, operands, &test_detail_riscv_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailRISCV *test_detail_riscv_new();
TestDetailRISCV *test_detail_riscv_clone(const TestDetailRISCV *detail);
void test_detail_riscv_free(TestDetailRISCV *detail);

TestDetailRISCVOp *test_detail_riscv_op_new();
TestDetailRISCVOp *test_detail_riscv_op_clone(const TestDetailRISCVOp *detail);
void test_detail_riscv_op_free(TestDetailRISCVOp *detail);

bool test_expected_riscv(csh *handle, const cs_riscv *actual,
			 const TestDetailRISCV *expected);

#endif // TEST_DETAIL_RISCV_H
