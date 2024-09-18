// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_M680X_H
#define TEST_DETAIL_M680X_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *base_reg;
	char *offset_reg;
	int16_t offset;
	uint16_t offset_addr;
	uint8_t offset_bits;
	int8_t inc_dec;
	char **flags;
	uint32_t flags_count;
} TestDetailM680xIdx;

static const cyaml_schema_value_t flag_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_detail_m680x_idx_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"base_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM680xIdx, base_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"offset_reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM680xIdx, offset_reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("offset", CYAML_FLAG_OPTIONAL, TestDetailM680xIdx,
			offset),
	CYAML_FIELD_UINT("offset_addr", CYAML_FLAG_OPTIONAL, TestDetailM680xIdx,
			offset_addr),
	CYAML_FIELD_UINT("offset_bits", CYAML_FLAG_OPTIONAL, TestDetailM680xIdx,
			offset_bits),
	CYAML_FIELD_INT("inc_dec", CYAML_FLAG_OPTIONAL, TestDetailM680xIdx,
			inc_dec),
	CYAML_FIELD_SEQUENCE("flags", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetailM680xIdx, flags, &flag_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX flags
	CYAML_FIELD_END
};

typedef struct {
	char *type;
	char *access;

	TestDetailM680xIdx *idx;
	char *reg;
	int32_t imm;
	uint16_t rel_address;
	uint16_t ext_address;
	int16_t rel_offset;
	tbool ext_indirect;
	uint8_t direct_addr;
	bool direct_addr_set;
	uint8_t const_val;
	uint8_t size;
} TestDetailM680xOp;

static const cyaml_schema_field_t test_detail_m680x_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM680xOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM680xOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_MAPPING_PTR("idx", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
				TestDetailM680xOp, idx,
				test_detail_m680x_idx_mapping_schema),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailM680xOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailM680xOp, imm),
	CYAML_FIELD_UINT("rel_address", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			 rel_address),
	CYAML_FIELD_UINT("ext_address", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			 ext_address),
	CYAML_FIELD_INT("rel_offset", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			rel_offset),
	CYAML_FIELD_INT("ext_indirect", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			ext_indirect),
	CYAML_FIELD_UINT("direct_addr", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			 direct_addr),
	CYAML_FIELD_BOOL("direct_addr_set", CYAML_FLAG_OPTIONAL,
			 TestDetailM680xOp, direct_addr_set),
	CYAML_FIELD_UINT("const_val", CYAML_FLAG_OPTIONAL, TestDetailM680xOp,
			 const_val),
	CYAML_FIELD_UINT("size", CYAML_FLAG_OPTIONAL, TestDetailM680xOp, size),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_m680x_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailM680xOp,
			    test_detail_m680x_op_mapping_schema),
};

typedef struct {
	char **flags;
	size_t flags_count;
	TestDetailM680xOp **operands;
	uint32_t operands_count;
} TestDetailM680x;

static const cyaml_schema_field_t test_detail_m680x_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE("flags", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			     TestDetailM680x, flags, &flag_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX flags
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailM680x, operands, &test_detail_m680x_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailM680x *test_detail_m680x_new();
TestDetailM680x *test_detail_m680x_clone(const TestDetailM680x *detail);
void test_detail_m680x_free(TestDetailM680x *detail);

TestDetailM680xOp *test_detail_m680x_op_new();
TestDetailM680xOp *test_detail_m680x_op_clone(const TestDetailM680xOp *detail);
void test_detail_m680x_op_free(TestDetailM680xOp *detail);

TestDetailM680xIdx *test_detail_m680x_idx_new();
TestDetailM680xIdx *
test_detail_m680x_idx_clone(const TestDetailM680xIdx *detail);
void test_detail_m680x_idx_free(TestDetailM680xIdx *detail);

bool test_expected_m680x(csh *handle, const cs_m680x *actual,
			 const TestDetailM680x *expected);

#endif // TEST_DETAIL_M680X_H
