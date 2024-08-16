// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_mips.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailMips *test_detail_mips_new()
{
	return cs_mem_calloc(sizeof(TestDetailMips), 1);
}

void test_detail_mips_free(TestDetailMips *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_mips_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailMips *test_detail_mips_clone(const TestDetailMips *detail)
{
	TestDetailMips *clone = test_detail_mips_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailMipsOp*),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_mips_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailMipsOp *test_detail_mips_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailMipsOp), 1);
}

TestDetailMipsOp *test_detail_mips_op_clone(const TestDetailMipsOp *op)
{
	TestDetailMipsOp *clone = test_detail_mips_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_mips_op_free(TestDetailMipsOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op);
}

bool test_expected_mips(csh *handle, const cs_mips *actual,
		       const TestDetailMips *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_mips_op *op = &actual->operands[i];
		TestDetailMipsOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"sh op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case MIPS_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case MIPS_OP_IMM:
			compare_uint64_ret(op->imm, eop->imm, false);
			break;
		case MIPS_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_int64_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}
