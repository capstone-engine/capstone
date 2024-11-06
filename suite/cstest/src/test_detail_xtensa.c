// Copyright © 2024 Rot127 <unisono@quyllur.org>
// Copyright © 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
#include <test_detail_xtensa.h>

TestDetailXtensa *test_detail_xtensa_new()
{
	return cs_mem_calloc(sizeof(TestDetailXtensa), 1);
}

void test_detail_xtensa_free(TestDetailXtensa *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_xtensa_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->format);
	cs_mem_free(detail);
}

TestDetailXtensa *test_detail_xtensa_clone(const TestDetailXtensa *detail)
{
	TestDetailXtensa *clone = test_detail_xtensa_new();
	clone->format = detail->format ? strdup(detail->format) : NULL;
	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailXtensaOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_xtensa_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailXtensaOp *test_detail_xtensa_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailXtensaOp), 1);
}

TestDetailXtensaOp *test_detail_xtensa_op_clone(const TestDetailXtensaOp *op)
{
	TestDetailXtensaOp *clone = test_detail_xtensa_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_xtensa_op_free(TestDetailXtensaOp *op)
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

bool test_expected_xtensa(csh *handle, const cs_xtensa *actual,
			  const TestDetailXtensa *expected)
{
	assert(handle && actual && expected);

	compare_enum_ret(actual->format, expected->format, false);
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_xtensa_op *op = &actual->operands[i];
		TestDetailXtensaOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"xtensa op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case XTENSA_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case XTENSA_OP_L32R:
		case XTENSA_OP_IMM:
			compare_int32_ret(op->imm, eop->imm, false);
			break;
		case XTENSA_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_int32_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}
