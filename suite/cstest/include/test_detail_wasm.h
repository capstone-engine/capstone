// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_WASM_H
#define TEST_DETAIL_WASM_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;

	uint32_t size;
	int8_t int7;
	uint32_t varuint32;
	uint64_t varuint64;
	uint32_t uint32;
	uint64_t uint64;
	uint32_t immediate_0;
	uint32_t immediate_1;
	uint32_t brt_length;
	uint64_t brt_address;
	uint32_t brt_default_target;
} TestDetailWASMOp;

static const cyaml_schema_field_t test_detail_wasm_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailWASMOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("size", CYAML_FLAG_OPTIONAL, TestDetailWASMOp, size),
	CYAML_FIELD_INT("int7", CYAML_FLAG_OPTIONAL, TestDetailWASMOp, int7),
	CYAML_FIELD_UINT("varuint32", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 varuint32),
	CYAML_FIELD_UINT("varuint64", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 varuint64),
	CYAML_FIELD_UINT("uint64", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 uint64),
	CYAML_FIELD_UINT("uint32", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 uint32),
	CYAML_FIELD_UINT("immediate_0", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 immediate_0),
	CYAML_FIELD_UINT("immediate_1", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 immediate_1),
	CYAML_FIELD_UINT("brt_length", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 brt_length),
	CYAML_FIELD_UINT("brt_address", CYAML_FLAG_OPTIONAL, TestDetailWASMOp,
			 brt_address),
	CYAML_FIELD_UINT("brt_default_target", CYAML_FLAG_OPTIONAL,
			 TestDetailWASMOp, brt_default_target),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_wasm_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailWASMOp,
			    test_detail_wasm_op_mapping_schema),
};

typedef struct {
	TestDetailWASMOp **operands;
	uint32_t operands_count;
} TestDetailWASM;

static const cyaml_schema_field_t test_detail_wasm_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailWASM, operands, &test_detail_wasm_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailWASM *test_detail_wasm_new();
TestDetailWASM *test_detail_wasm_clone(const TestDetailWASM *detail);
void test_detail_wasm_free(TestDetailWASM *detail);

TestDetailWASMOp *test_detail_wasm_op_new();
TestDetailWASMOp *test_detail_wasm_op_clone(const TestDetailWASMOp *detail);
void test_detail_wasm_op_free(TestDetailWASMOp *detail);

bool test_expected_wasm(csh *handle, const cs_wasm *actual,
			const TestDetailWASM *expected);

#endif // TEST_DETAIL_WASM_H
