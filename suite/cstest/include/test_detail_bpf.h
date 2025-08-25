// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_BPF_H
#define TEST_DETAIL_BPF_H

#include "test_compare.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	char *type;
	char *access;

	char *reg;
	uint64_t imm;
	uint32_t off;
	uint32_t mmem;
	uint32_t msh;
	char *ext;
	char *mem_base;
	uint32_t mem_disp;
	tbool is_pkt;
	tbool is_signed;
} TestDetailBPFOp;

static const cyaml_schema_field_t test_detail_bpf_op_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("type", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailBPFOp, type, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("access",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailBPFOp, access, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("reg", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailBPFOp, reg, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("imm", CYAML_FLAG_OPTIONAL, TestDetailBPFOp, imm),
	CYAML_FIELD_UINT("off", CYAML_FLAG_OPTIONAL, TestDetailBPFOp, off),
	CYAML_FIELD_UINT("mmem", CYAML_FLAG_OPTIONAL, TestDetailBPFOp, mmem),
	CYAML_FIELD_UINT("msh", CYAML_FLAG_OPTIONAL, TestDetailBPFOp, msh),
	CYAML_FIELD_STRING_PTR("ext", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailBPFOp, ext, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("mem_base",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestDetailBPFOp, mem_base, 0, CYAML_UNLIMITED),
	CYAML_FIELD_UINT("mem_disp", CYAML_FLAG_OPTIONAL, TestDetailBPFOp,
			 mem_disp),
	CYAML_FIELD_TBOOL("is_pkt", CYAML_FLAG_OPTIONAL, TestDetailBPFOp,
			  is_pkt),
	CYAML_FIELD_TBOOL("is_signed", CYAML_FLAG_OPTIONAL, TestDetailBPFOp,
			  is_signed),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_detail_bpf_op_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestDetailBPFOp,
			    test_detail_bpf_op_mapping_schema),
};

typedef struct {
	TestDetailBPFOp **operands;
	uint32_t operands_count;
} TestDetailBPF;

static const cyaml_schema_field_t test_detail_bpf_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"operands", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestDetailBPF, operands, &test_detail_bpf_op_schema, 0,
		CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

TestDetailBPF *test_detail_bpf_new();
TestDetailBPF *test_detail_bpf_clone(const TestDetailBPF *detail);
void test_detail_bpf_free(TestDetailBPF *detail);

TestDetailBPFOp *test_detail_bpf_op_new();
TestDetailBPFOp *test_detail_bpf_op_clone(const TestDetailBPFOp *detail);
void test_detail_bpf_op_free(TestDetailBPFOp *detail);

bool test_expected_bpf(csh *handle, const cs_bpf *actual,
		       const TestDetailBPF *expected);

#endif // TEST_DETAIL_BPF_H
