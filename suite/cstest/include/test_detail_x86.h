// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_X86_H
#define TEST_DETAIL_X86_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>
#include <stdint.h>

typedef struct {
	char *type;
	char *access;
	uint8_t size;

	char *reg;
	int64_t imm;
	char *mem_segment;
	char *mem_base;
	char *mem_index;
	int mem_scale;
	int64_t mem_disp;

	char *avx_bcast;
	tbool avx_zero_opmask;
} TestDetailX86Op;

static const cyaml_schema_value_t test_detail_x86_op_sys_psr_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_x86_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("size", CYAML_FLAG_OPTIONAL, TestDetailX86Op, size),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailX86Op, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_segment", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailX86Op, mem_segment, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_index",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailX86Op,
			mem_disp),
	CYAML_FIELD_INT("mem_scale", CYAML_FLAG_OPTIONAL, TestDetailX86Op,
			mem_scale),
	CYAML_FIELD_INT("avx_zero_opmask", CYAML_FLAG_OPTIONAL, TestDetailX86Op,
			avx_zero_opmask),
	CYAML_FIELD_STRING_PTR("avx_bcast",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86Op, avx_bcast, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_x86_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailX86Op,
			    test_detail_x86_op_mapping_schema),
};

static const cyaml_schema_value_t test_detail_x86_opcode_schema = {
	CYAML_VALUE_UINT(CYAML_FLAG_DEFAULT, uint8_t),
};

static const cyaml_schema_value_t test_detail_x86_string_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

typedef struct {
	char *sib_index;
	char *sib_base;
	char *xop_cc;
	char *sse_cc;
	char *avx_cc;
	char *avx_rm;

	char *prefix[4];
	uint8_t opcode[4];

	uint8_t rex;
	uint8_t addr_size;
	uint8_t modrm;
	uint8_t sib;
	int64_t disp;
	int8_t sib_scale;
	tbool avx_sae;

	char **eflags;
	size_t eflags_count;
	char **fpu_flags;
	size_t fpu_flags_count;

	uint8_t enc_modrm_offset;
	uint8_t enc_disp_offset;
	uint8_t enc_disp_size;
	uint8_t enc_imm_offset;
	uint8_t enc_imm_size;

	TestDetailX86Op **operands;
	uint32_t operands_count;
} TestDetailX86;

static const cyaml_schema_field_t test_detail_x86_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("sib_index",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, sib_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("sib_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, sib_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("xop_cc",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, xop_cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("sse_cc",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, sse_cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("avx_cc",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, avx_cc, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("avx_rm",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailX86, avx_rm, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE_FIXED("prefix", CYAML_FLAG_OPTIONAL, TestDetailX86,
				   prefix, &test_detail_x86_string_schema, 4),
	CYAML_FIELD_SEQUENCE_FIXED("opcode", CYAML_FLAG_OPTIONAL, TestDetailX86,
				   opcode, &test_detail_x86_opcode_schema, 4),
	CYAML_FIELD_UINT("rex", CYAML_FLAG_OPTIONAL, TestDetailX86, rex),
	CYAML_FIELD_UINT("addr_size", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 addr_size),
	CYAML_FIELD_UINT("modrm", CYAML_FLAG_OPTIONAL, TestDetailX86, modrm),
	CYAML_FIELD_UINT("sib", CYAML_FLAG_OPTIONAL, TestDetailX86, sib),
	CYAML_FIELD_INT("disp", CYAML_FLAG_OPTIONAL, TestDetailX86, disp),
	CYAML_FIELD_INT("sib_scale", CYAML_FLAG_OPTIONAL, TestDetailX86,
			sib_scale),
	CYAML_FIELD_INT("avx_sae", CYAML_FLAG_OPTIONAL, TestDetailX86, avx_sae),
	CYAML_FIELD_SEQUENCE("eflags", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetailX86, eflags,
			     &test_detail_x86_string_schema, 0,
			     CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"fpu_flags", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailX86, fpu_flags, &test_detail_x86_string_schema, 0,
		CYAML_UNLIMITED),
	CYAML_FIELD_UINT("enc_modrm_offset", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 enc_modrm_offset),
	CYAML_FIELD_UINT("enc_disp_offset", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 enc_disp_offset),
	CYAML_FIELD_UINT("enc_disp_size", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 enc_disp_size),
	CYAML_FIELD_UINT("enc_imm_offset", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 enc_imm_offset),
	CYAML_FIELD_UINT("enc_imm_size", CYAML_FLAG_OPTIONAL, TestDetailX86,
			 enc_imm_size),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailX86, operands, &test_detail_x86_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailX86 *test_detail_x86_new();
TestDetailX86 *test_detail_x86_clone(TestDetailX86 *detail);
void test_detail_x86_free(TestDetailX86 *detail);

TestDetailX86Op *test_detail_x86_op_new();
TestDetailX86Op *test_detail_x86_op_clone(TestDetailX86Op *detail);
void test_detail_x86_op_free(TestDetailX86Op *detail);

bool test_expected_x86(csh *handle, cs_x86 *actual, TestDetailX86 *expected);

#endif // TEST_DETAIL_X86_H
