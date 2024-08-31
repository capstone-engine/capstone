// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_ARM_H
#define TEST_DETAIL_ARM_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
	char *setend;
	int pred;
	double fp;
	char *mem_base;
	char *mem_index;
	int32_t mem_scale;
	int32_t mem_disp;
	uint32_t mem_align;
	char *sys_reg;
	char **sys_psr_bits;
	uint32_t sys_psr_bits_count;
	int sys_sysm;
	int sys_msr_mask;

	char *shift_type;
	uint32_t shift_value;

	int8_t neon_lane;
	int vector_index;
	bool vector_index_is_set;

	tbool subtracted;
} TestDetailARMOp;

static const cyaml_schema_value_t test_detail_arm_op_sys_psr_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_arm_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailARMOp, imm),
	CYAML_FIELD_STRING_PTR("setend",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, setend, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("pred", CYAML_FLAG_OPTIONAL, TestDetailARMOp, pred),
	CYAML_FIELD_FLOAT("fp", CYAML_FLAG_OPTIONAL, TestDetailARMOp, fp),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_index",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			mem_disp),
	CYAML_FIELD_INT("mem_scale", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			mem_scale),
	CYAML_FIELD_UINT("mem_align", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			 mem_align),
	CYAML_FIELD_STRING_PTR("sys_reg",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, sys_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"sys_psr_bits", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailARMOp, sys_psr_bits,
		&test_detail_arm_op_sys_psr_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("sys_sysm", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			sys_sysm),
	CYAML_FIELD_INT("sys_msr_mask", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			sys_msr_mask),
	CYAML_FIELD_STRING_PTR("shift_type",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARMOp, shift_type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("shift_value", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			 shift_value),
	CYAML_FIELD_INT("neon_lane", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			neon_lane),
	CYAML_FIELD_INT("vector_index", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			vector_index),
	CYAML_FIELD_BOOL("vector_index_is_set", CYAML_FLAG_OPTIONAL,
			 TestDetailARMOp, vector_index_is_set),
	CYAML_FIELD_INT("subtracted", CYAML_FLAG_OPTIONAL, TestDetailARMOp,
			subtracted),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_arm_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailARMOp,
			    test_detail_arm_op_mapping_schema),
};

typedef struct {
	int vector_size;
	char *vector_data;
	char *cps_mode;
	char *cps_flag;
	char *cc;
	char *vcc;
	char *mem_barrier;
	uint8_t pred_mask;

	tbool usermode;
	tbool update_flags;
	tbool post_indexed;

	TestDetailARMOp **operands;
	uint32_t operands_count;
} TestDetailARM;

static const cyaml_schema_field_t test_detail_arm_mapping_schema[] = {
	CYAML_FIELD_INT("vector_size", CYAML_FLAG_OPTIONAL, TestDetailARM,
			vector_size),
	CYAML_FIELD_STRING_PTR("vector_data",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, vector_data, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("cps_mode",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, cps_mode, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("cps_flag",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, cps_flag, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("cc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("vcc", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, vcc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_barrier",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailARM, mem_barrier, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("pred_mask", CYAML_FLAG_OPTIONAL, TestDetailARM,
			 pred_mask),
	CYAML_FIELD_INT("usermode", CYAML_FLAG_OPTIONAL, TestDetailARM,
			usermode),
	CYAML_FIELD_INT("update_flags", CYAML_FLAG_OPTIONAL, TestDetailARM,
			update_flags),
	CYAML_FIELD_INT("post_indexed", CYAML_FLAG_OPTIONAL, TestDetailARM,
			post_indexed),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailARM, operands, &test_detail_arm_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailARM *test_detail_arm_new();
TestDetailARM *test_detail_arm_clone(TestDetailARM *detail);
void test_detail_arm_free(TestDetailARM *detail);

TestDetailARMOp *test_detail_arm_op_new();
TestDetailARMOp *test_detail_arm_op_clone(TestDetailARMOp *detail);
void test_detail_arm_op_free(TestDetailARMOp *detail);

bool test_expected_arm(csh *handle, cs_arm *actual, TestDetailARM *expected);

#endif // TEST_DETAIL_ARM_H
