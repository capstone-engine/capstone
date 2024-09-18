// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_TMS320C64X_H
#define TEST_DETAIL_TMS320C64X_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	char *reg;
	char *reg_pair_0;
	char *reg_pair_1;
	int32_t imm;
	char *mem_base;
	tbool mem_scaled;
	char *mem_disptype;
	char *mem_direction;
	char *mem_modify;
	char *mem_disp_reg;
	unsigned int mem_disp_const;
	unsigned int mem_unit;
} TestDetailTMS320c64xOp;

static const cyaml_schema_value_t test_detail_tms320c64x_op_sys_psr_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_tms320c64x_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailTMS320c64xOp, type, 0,
			       CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailTMS320c64xOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"reg_pair_0", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, reg_pair_0, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"reg_pair_1", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, reg_pair_1, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailTMS320c64xOp,
			imm),
	CYAML_FIELD_INT("mem_scaled", CYAML_FLAG_OPTIONAL,
			TestDetailTMS320c64xOp, mem_scaled),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_disptype", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, mem_disptype, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_direction", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, mem_direction, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_modify", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, mem_modify, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("mem_disp_const", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64xOp, mem_disp_const),
	CYAML_FIELD_STRING_PTR(
		"mem_disp_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64xOp, mem_disp_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("mem_unit", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64xOp, mem_unit),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_tms320c64x_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailTMS320c64xOp,
			    test_detail_tms320c64x_op_mapping_schema),
};

typedef struct {
	char *cond_reg;
	tbool cond_zero;

	char *funit_unit;
	uint8_t funit_side;
	bool funit_side_set;
	uint8_t funit_crosspath;
	bool funit_crosspath_set;

	int8_t parallel;
	bool parallel_set;

	TestDetailTMS320c64xOp **operands;
	uint32_t operands_count;
} TestDetailTMS320c64x;

static const cyaml_schema_field_t test_detail_tms320c64x_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"cond_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64x, cond_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("cond_zero", CYAML_FLAG_OPTIONAL, TestDetailTMS320c64x,
			cond_zero),
	CYAML_FIELD_STRING_PTR(
		"funit_unit", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailTMS320c64x, funit_unit, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("funit_side", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64x, funit_side),
	CYAML_FIELD_BOOL("funit_side_set", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64x, funit_side_set),
	CYAML_FIELD_UINT("funit_crosspath", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64x, funit_crosspath),
	CYAML_FIELD_BOOL("funit_crosspath_set", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64x, funit_crosspath_set),
	CYAML_FIELD_INT("parallel", CYAML_FLAG_OPTIONAL, TestDetailTMS320c64x,
			parallel),
	CYAML_FIELD_BOOL("parallel_set", CYAML_FLAG_OPTIONAL,
			 TestDetailTMS320c64x, parallel_set),
	CYAML_FIELD_SEQUENCE("operands",
			     CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetailTMS320c64x, operands,
			     &test_detail_tms320c64x_op_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailTMS320c64x *test_detail_tms320c64x_new();
TestDetailTMS320c64x *
test_detail_tms320c64x_clone(TestDetailTMS320c64x *detail);
void test_detail_tms320c64x_free(TestDetailTMS320c64x *detail);

TestDetailTMS320c64xOp *test_detail_tms320c64x_op_new();
TestDetailTMS320c64xOp *
test_detail_tms320c64x_op_clone(TestDetailTMS320c64xOp *detail);
void test_detail_tms320c64x_op_free(TestDetailTMS320c64xOp *detail);

bool test_expected_tms320c64x(csh *handle, cs_tms320c64x *actual,
			      TestDetailTMS320c64x *expected);

#endif // TEST_DETAIL_TMS320C64X_H
