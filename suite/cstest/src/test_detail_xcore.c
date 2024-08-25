// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_xcore.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailXCore *test_detail_xcore_new()
{
	return cs_mem_calloc(sizeof(TestDetailXCore), 1);
}

void test_detail_xcore_free(TestDetailXCore *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_xcore_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailXCore *test_detail_xcore_clone(const TestDetailXCore *detail)
{
	TestDetailXCore *clone = test_detail_xcore_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailXCoreOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_xcore_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailXCoreOp *test_detail_xcore_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailXCoreOp), 1);
}

TestDetailXCoreOp *test_detail_xcore_op_clone(const TestDetailXCoreOp *op)
{
	TestDetailXCoreOp *clone = test_detail_xcore_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->mem_disp = op->mem_disp;
	clone->mem_direct = op->mem_direct;

	return clone;
}

void test_detail_xcore_op_free(TestDetailXCoreOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op);
}

bool test_expected_xcore(csh *handle, const cs_xcore *actual,
			 const TestDetailXCore *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_xcore_op *op = &actual->operands[i];
		TestDetailXCoreOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case XCORE_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case XCORE_OP_IMM:
			compare_int32_ret(op->imm, eop->imm, false);
			break;
		case XCORE_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
			compare_int_ret(op->mem.disp, eop->mem_disp, false);
			if (eop->mem_direct) {
				compare_int_ret(op->mem.direct, eop->mem_direct,
						false);
			}
			break;
		}
	}

	return true;
}
