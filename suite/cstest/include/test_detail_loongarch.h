// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_LOONGARCH_H
#define TEST_DETAIL_LOONGARCH_H

#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	uint64_t imm;
	char *mem_base;
	char *mem_index;
	int64_t mem_disp;
} TestDetailLoongArchOp;

static const cyaml_schema_field_t test_detail_loongarch_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailLoongArchOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"access", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailLoongArchOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailLoongArchOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailLoongArchOp, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailLoongArchOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mem_index", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailLoongArchOp, mem_index, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailLoongArchOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_loongarch_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailLoongArchOp,
			    test_detail_loongarch_op_mapping_schema),
};

typedef struct {
	char *format;
	TestDetailLoongArchOp **operands;
	uint32_t operands_count;
} TestDetailLoongArch;

static const cyaml_schema_field_t test_detail_loongarch_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("format",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailLoongArch, format, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE("operands",
			     CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetailLoongArch, operands,
			     &test_detail_loongarch_op_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailLoongArch *test_detail_loongarch_new();
TestDetailLoongArch *
test_detail_loongarch_clone(const TestDetailLoongArch *detail);
void test_detail_loongarch_free(TestDetailLoongArch *detail);

TestDetailLoongArchOp *test_detail_loongarch_op_new();
TestDetailLoongArchOp *
test_detail_loongarch_op_clone(const TestDetailLoongArchOp *detail);
void test_detail_loongarch_op_free(TestDetailLoongArchOp *detail);

bool test_expected_loongarch(csh *handle, const cs_loongarch *actual,
			     const TestDetailLoongArch *expected);

#endif // TEST_DETAIL_LOONGARCH_H
