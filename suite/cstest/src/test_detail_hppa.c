// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "capstone/hppa.h"
#include "test_compare.h"
#include "test_detail_hppa.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailHPPA *test_detail_hppa_new()
{
	return cs_mem_calloc(sizeof(TestDetailHPPA), 1);
}

void test_detail_hppa_free(TestDetailHPPA *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_hppa_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailHPPA *test_detail_hppa_clone(const TestDetailHPPA *detail)
{
	TestDetailHPPA *clone = test_detail_hppa_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailHPPAOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_hppa_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailHPPAOp *test_detail_hppa_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailHPPAOp), 1);
}

TestDetailHPPAOp *test_detail_hppa_op_clone(const TestDetailHPPAOp *op)
{
	TestDetailHPPAOp *clone = test_detail_hppa_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_space = op->mem_space ? strdup(op->mem_space) : NULL;

	return clone;
}

void test_detail_hppa_op_free(TestDetailHPPAOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_space);
	cs_mem_free(op);
}

bool test_expected_hppa(csh *handle, const cs_hppa *actual,
			const TestDetailHPPA *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_hppa_op *op = &actual->operands[i];
		TestDetailHPPAOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"hppa op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case HPPA_OP_REG:
		case HPPA_OP_IDX_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case HPPA_OP_DISP:
		case HPPA_OP_IMM:
		case HPPA_OP_TARGET:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case HPPA_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.space, eop->mem_space,
					false);
			break;
		}
	}

	return true;
}
