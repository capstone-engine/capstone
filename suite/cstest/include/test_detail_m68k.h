// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_M68K_H
#define TEST_DETAIL_M68K_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *base_reg;
	char *index_reg;
	char *in_base_reg;
	tbool index_size; // -1 == word, 1 == long
	int16_t disp;
	uint32_t in_disp;
	uint32_t out_disp;
	uint8_t scale;
	uint8_t bitfield;
	uint8_t width;
	uint8_t offset;
} TestDetailM68KOpMem;

static const cyaml_schema_field_t test_detail_m68k_op_mem_mapping_schema[] = {
	CYAML_FIELD_INT("disp", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem, disp),
	CYAML_FIELD_STRING_PTR(
		"base_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOpMem, base_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"index_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOpMem, index_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"in_base_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOpMem, in_base_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("index_size", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			TestDetailM68KOpMem, index_size),
	CYAML_FIELD_INT("disp", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem, disp),
	CYAML_FIELD_UINT("in_disp", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 in_disp),
	CYAML_FIELD_UINT("out_disp", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 out_disp),
	CYAML_FIELD_UINT("scale", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 scale),
	CYAML_FIELD_UINT("bitfield", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 bitfield),
	CYAML_FIELD_UINT("width", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 width),
	CYAML_FIELD_UINT("offset", CYAML_FLAG_OPTIONAL, TestDetailM68KOpMem,
			 offset),
	CYAML_FIELD_END
};

typedef struct {
	char *type;
	char *address_mode;

	char *reg;
	char *reg_pair_0;
	char *reg_pair_1;

	uint64_t imm;
	int32_t br_disp;
	uint8_t br_disp_size;

	uint32_t register_bits;

	double dimm;
	float simm;

	TestDetailM68KOpMem *mem;
} TestDetailM68KOp;

static const cyaml_schema_value_t test_detail_m68k_op_sys_psr_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_m68k_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM68KOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"address_mode", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOp, address_mode, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM68KOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"reg_pair_0", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOp, reg_pair_0, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"reg_pair_1", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68KOp, reg_pair_1, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailM68KOp, imm),
	CYAML_FIELD_INT("br_disp", CYAML_FLAG_OPTIONAL, TestDetailM68KOp,
			br_disp),
	CYAML_FIELD_UINT("br_disp_size", CYAML_FLAG_OPTIONAL, TestDetailM68KOp,
			 br_disp_size),
	CYAML_FIELD_UINT("register_bits", CYAML_FLAG_OPTIONAL, TestDetailM68KOp,
			 register_bits),
	CYAML_FIELD_FLOAT("dimm", CYAML_FLAG_OPTIONAL, TestDetailM68KOp, dimm),
	CYAML_FIELD_FLOAT("simm", CYAML_FLAG_OPTIONAL, TestDetailM68KOp, simm),
	CYAML_FIELD_MAPPING_PTR("mem", CYAML_FLAG_OPTIONAL, TestDetailM68KOp,
				mem, test_detail_m68k_op_mem_mapping_schema),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_m68k_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailM68KOp,
			    test_detail_m68k_op_mapping_schema),
};

typedef struct {
	char *op_size_type;
	char *op_size_fpu;
	char *op_size_cpu;

	TestDetailM68KOp **operands;
	uint32_t operands_count;
} TestDetailM68K;

static const cyaml_schema_field_t test_detail_m68k_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"op_size_type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68K, op_size_type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("op_size_fpu",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM68K, op_size_fpu, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("op_size_cpu",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM68K, op_size_cpu, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM68K, operands, &test_detail_m68k_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailM68K *test_detail_m68k_new();
TestDetailM68K *test_detail_m68k_clone(TestDetailM68K *detail);
void test_detail_m68k_free(TestDetailM68K *detail);

TestDetailM68KOp *test_detail_m68k_op_new();
TestDetailM68KOp *test_detail_m68k_op_clone(TestDetailM68KOp *detail);
void test_detail_m68k_op_free(TestDetailM68KOp *detail);

TestDetailM68KOpMem *test_detail_m68k_op_mem_new();
TestDetailM68KOpMem *test_detail_m68k_op_mem_clone(TestDetailM68KOpMem *detail);
void test_detail_m68k_op_mem_free(TestDetailM68KOpMem *detail);

bool test_expected_m68k(csh *handle, cs_m68k *actual, TestDetailM68K *expected);

#endif // TEST_DETAIL_M68K_H
