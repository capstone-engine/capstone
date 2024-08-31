// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_MOS65XX_H
#define TEST_DETAIL_MOS65XX_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	char *reg;
	uint16_t imm;
	uint32_t mem;
} TestDetailMos65xxOp;

static const cyaml_schema_field_t test_detail_mos65xx_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMos65xxOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMos65xxOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("imm", CYAML_FLAG_OPTIONAL, TestDetailMos65xxOp, imm),
	CYAML_FIELD_UINT("mem", CYAML_FLAG_OPTIONAL, TestDetailMos65xxOp, mem),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_mos65xx_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailMos65xxOp,
			    test_detail_mos65xx_op_mapping_schema),
};

typedef struct {
	char *am;
	tbool modifies_flags;

	TestDetailMos65xxOp **operands;
	uint32_t operands_count;
} TestDetailMos65xx;

static const cyaml_schema_field_t test_detail_mos65xx_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("am", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailMos65xx, am, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("modifies_flags", CYAML_FLAG_OPTIONAL,
			TestDetailMos65xx, modifies_flags),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailMos65xx, operands, &test_detail_mos65xx_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailMos65xx *test_detail_mos65xx_new();
TestDetailMos65xx *test_detail_mos65xx_clone(const TestDetailMos65xx *detail);
void test_detail_mos65xx_free(TestDetailMos65xx *detail);

TestDetailMos65xxOp *test_detail_mos65xx_op_new();
TestDetailMos65xxOp *
test_detail_mos65xx_op_clone(const TestDetailMos65xxOp *detail);
void test_detail_mos65xx_op_free(TestDetailMos65xxOp *detail);

bool test_expected_mos65xx(csh *handle, const cs_mos65xx *actual,
			   const TestDetailMos65xx *expected);

#endif // TEST_DETAIL_MOS65XX_H
