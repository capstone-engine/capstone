// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_sh.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailSH *test_detail_sh_new()
{
	return cs_mem_calloc(sizeof(TestDetailSH), 1);
}

void test_detail_sh_free(TestDetailSH *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_sh_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailSH *test_detail_sh_clone(const TestDetailSH *detail)
{
	TestDetailSH *clone = test_detail_sh_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailSHOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_sh_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailSHOp *test_detail_sh_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailSHOp), 1);
}

TestDetailSHOp *test_detail_sh_op_clone(const TestDetailSHOp *op)
{
	TestDetailSHOp *clone = test_detail_sh_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_reg = op->mem_reg ? strdup(op->mem_reg) : NULL;
	clone->mem_address = op->mem_address ? strdup(op->mem_address) : NULL;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_sh_op_free(TestDetailSHOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_reg);
	cs_mem_free(op->mem_address);
	cs_mem_free(op);
}

bool test_expected_sh(csh *handle, const cs_sh *actual,
		      const TestDetailSH *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_sh_op *op = &actual->operands[i];
		TestDetailSHOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr, "sh op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case SH_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case SH_OP_IMM:
			compare_uint64_ret(op->imm, eop->imm, false);
			break;
		case SH_OP_MEM:
			compare_reg_ret(*handle, op->mem.reg, eop->mem_reg,
					false);
			compare_reg_ret(*handle, op->mem.address,
					eop->mem_address, false);
			compare_int_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}
