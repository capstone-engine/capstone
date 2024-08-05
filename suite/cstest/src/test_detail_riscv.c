// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_riscv.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailRISCV *test_detail_riscv_new()
{
	return cs_mem_calloc(sizeof(TestDetailRISCV), 1);
}

void test_detail_riscv_free(TestDetailRISCV *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_riscv_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailRISCV *test_detail_riscv_clone(const TestDetailRISCV *detail)
{
	TestDetailRISCV *clone = test_detail_riscv_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailRISCVOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_riscv_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailRISCVOp *test_detail_riscv_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailRISCVOp), 1);
}

TestDetailRISCVOp *test_detail_riscv_op_clone(const TestDetailRISCVOp *op)
{
	TestDetailRISCVOp *clone = test_detail_riscv_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_riscv_op_free(TestDetailRISCVOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op);
}

bool test_expected_riscv(csh *handle, const cs_riscv *actual,
			 const TestDetailRISCV *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_riscv_op *op = &actual->operands[i];
		TestDetailRISCVOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr, "sh op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case RISCV_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case RISCV_OP_IMM:
			compare_uint64_ret(op->imm, eop->imm, false);
			break;
		case RISCV_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_int64_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}
