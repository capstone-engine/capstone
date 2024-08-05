// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_mos65xx.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailMos65xx *test_detail_mos65xx_new()
{
	return cs_mem_calloc(sizeof(TestDetailMos65xx), 1);
}

void test_detail_mos65xx_free(TestDetailMos65xx *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_mos65xx_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->am);
	cs_mem_free(detail);
}

TestDetailMos65xx *test_detail_mos65xx_clone(const TestDetailMos65xx *detail)
{
	TestDetailMos65xx *clone = test_detail_mos65xx_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailMos65xxOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_mos65xx_op_clone(detail->operands[i]);
	}
	clone->am = detail->am ? strdup(detail->am) : NULL;
	clone->modifies_flags = detail->modifies_flags;

	return clone;
}

TestDetailMos65xxOp *test_detail_mos65xx_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailMos65xxOp), 1);
}

TestDetailMos65xxOp *test_detail_mos65xx_op_clone(const TestDetailMos65xxOp *op)
{
	TestDetailMos65xxOp *clone = test_detail_mos65xx_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem = op->mem;

	return clone;
}

void test_detail_mos65xx_op_free(TestDetailMos65xxOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op);
}

bool test_expected_mos65xx(csh *handle, const cs_mos65xx *actual,
			   const TestDetailMos65xx *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	compare_enum_ret(actual->am, expected->am, false);
	compare_tbool_ret(actual->modifies_flags, expected->modifies_flags,
			  false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_mos65xx_op *op = &actual->operands[i];
		TestDetailMos65xxOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr, "sh op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case MOS65XX_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case MOS65XX_OP_IMM:
			compare_uint16_ret(op->imm, eop->imm, false);
			break;
		case MOS65XX_OP_MEM:
			compare_uint16_ret(op->mem, eop->mem, false);
			break;
		}
	}

	return true;
}
