// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_PPC_H
#define TEST_DETAIL_PPC_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	int64_t imm;
	char *mem_base;
	char *mem_offset;
	int32_t mem_disp;
} TestDetailPPCOp;

static const cyaml_schema_field_t test_detail_ppc_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("imm", CYAML_FLAG_OPTIONAL, TestDetailPPCOp, imm),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_offset",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCOp, mem_offset, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailPPCOp,
			mem_disp),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_ppc_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailPPCOp,
			    test_detail_ppc_op_mapping_schema),
};

typedef struct {
	uint8_t bo;
	bool bo_set;
	uint8_t bi;
	bool bi_set;

	char *crX_bit;
	char *crX;
	char *hint;
	char *pred_cr;
	char *pred_ctr;
	char *bh;
} TestDetailPPCBC;

static const cyaml_schema_field_t test_detail_ppc_bc_mapping_schema[] = {
	CYAML_FIELD_INT("bi", CYAML_FLAG_OPTIONAL, TestDetailPPCBC, bi),
	CYAML_FIELD_BOOL("bi_set", CYAML_FLAG_OPTIONAL, TestDetailPPCBC,
			 bi_set),
	CYAML_FIELD_INT("bo", CYAML_FLAG_OPTIONAL, TestDetailPPCBC, bo),
	CYAML_FIELD_BOOL("bo_set", CYAML_FLAG_OPTIONAL, TestDetailPPCBC,
			 bo_set),
	CYAML_FIELD_STRING_PTR("crX_bit",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, crX_bit, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("crX", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, crX, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("hint", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, hint, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("pred_cr",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, pred_cr, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("pred_ctr",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, pred_ctr, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("bh", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPCBC, bh, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

typedef struct {
	TestDetailPPCBC *bc;
	tbool update_cr0;
	char *format;
	TestDetailPPCOp **operands;
	uint32_t operands_count;
} TestDetailPPC;

static const cyaml_schema_field_t test_detail_ppc_mapping_schema[] = {
	CYAML_FIELD_MAPPING_PTR("bc", CYAML_FLAG_OPTIONAL, TestDetailPPC, bc,
				test_detail_ppc_bc_mapping_schema),
	CYAML_FIELD_STRING_PTR("format",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailPPC, format, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("update_cr0", CYAML_FLAG_OPTIONAL, TestDetailPPC,
			update_cr0),
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailPPC, operands, &test_detail_ppc_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailPPC *test_detail_ppc_new();
TestDetailPPC *test_detail_ppc_clone(const TestDetailPPC *detail);
void test_detail_ppc_free(TestDetailPPC *detail);

TestDetailPPCOp *test_detail_ppc_op_new();
TestDetailPPCOp *test_detail_ppc_op_clone(const TestDetailPPCOp *detail);
void test_detail_ppc_op_free(TestDetailPPCOp *detail);

TestDetailPPCBC *test_detail_ppc_bc_new();
TestDetailPPCBC *test_detail_ppc_bc_clone(const TestDetailPPCBC *detail);
void test_detail_ppc_bc_free(TestDetailPPCBC *detail);

bool test_expected_ppc(csh *handle, const cs_ppc *actual,
		       const TestDetailPPC *expected);

#endif // TEST_DETAIL_PPC_H
