// Copyright © 2024 Rot127 <unisono@quyllur.org>
// Copyright © 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_XTENSA_H
#define TEST_DETAIL_XTENSA_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int32_t imm;
	char *mem_base;
	int32_t mem_disp;
} TestDetailXtensaOp;

static const cyaml_schema_field_t test_detail_xtensa_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXtensaOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXtensaOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXtensaOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailXtensaOp, imm),
	CYAML_FIELD_STRING_PTR(
		"mem_base", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailXtensaOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailXtensaOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_xtensa_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailXtensaOp,
			    test_detail_xtensa_op_mapping_schema),
};

typedef struct {
	TestDetailXtensaOp **operands;
	uint32_t operands_count;
	char *format;
} TestDetailXtensa;

static const cyaml_schema_field_t test_detail_xtensa_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailXtensa, operands, &test_detail_xtensa_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_STRING_PTR("format",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailXtensa, format, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

TestDetailXtensa *test_detail_xtensa_new();
TestDetailXtensa *test_detail_xtensa_clone(const TestDetailXtensa *detail);
void test_detail_xtensa_free(TestDetailXtensa *detail);

TestDetailXtensaOp *test_detail_xtensa_op_new();
TestDetailXtensaOp *
test_detail_xtensa_op_clone(const TestDetailXtensaOp *detail);
void test_detail_xtensa_op_free(TestDetailXtensaOp *detail);

bool test_expected_xtensa(csh *handle, const cs_xtensa *actual,
			  const TestDetailXtensa *expected);

#endif // TEST_DETAIL_XTENSA_H
