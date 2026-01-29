// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_alpha.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailAlpha *test_detail_alpha_new()
{
	return cs_mem_calloc(sizeof(TestDetailAlpha), 1);
}

void test_detail_alpha_free(TestDetailAlpha *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_alpha_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailAlpha *test_detail_alpha_clone(const TestDetailAlpha *detail)
{
	TestDetailAlpha *clone = test_detail_alpha_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailAlphaOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_alpha_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailAlphaOp *test_detail_alpha_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailAlphaOp), 1);
}

TestDetailAlphaOp *test_detail_alpha_op_clone(const TestDetailAlphaOp *op)
{
	TestDetailAlphaOp *clone = test_detail_alpha_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;

	return clone;
}

void test_detail_alpha_op_free(TestDetailAlphaOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op);
}

bool test_expected_alpha(csh *handle, const cs_alpha *actual,
			 const TestDetailAlpha *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_alpha_op *op = &actual->operands[i];
		TestDetailAlphaOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"alpha op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case ALPHA_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case ALPHA_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		}
	}

	return true;
}
