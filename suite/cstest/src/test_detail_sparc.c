// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_sparc.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailSparc *test_detail_sparc_new()
{
	return cs_mem_calloc(sizeof(TestDetailSparc), 1);
}

void test_detail_sparc_free(TestDetailSparc *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_sparc_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->cc);
	cs_mem_free(detail->cc_field);
	cs_mem_free(detail->hint);
	cs_mem_free(detail);
}

TestDetailSparc *test_detail_sparc_clone(const TestDetailSparc *detail)
{
	TestDetailSparc *clone = test_detail_sparc_new();

	clone->operands_count = detail->operands_count;
	clone->cc = detail->cc ? strdup(detail->cc) : NULL;
	clone->cc_field = detail->cc_field ? strdup(detail->cc_field) : NULL;
	clone->hint = detail->hint ? strdup(detail->hint) : NULL;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailSparcOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_sparc_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailSparcOp *test_detail_sparc_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailSparcOp), 1);
}

TestDetailSparcOp *test_detail_sparc_op_clone(const TestDetailSparcOp *op)
{
	TestDetailSparcOp *clone = test_detail_sparc_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->mem_disp = op->mem_disp;
	clone->asi = op->asi ? strdup(op->asi) : NULL;
	clone->membar_tag = op->membar_tag ? strdup(op->membar_tag) : NULL;

	return clone;
}

void test_detail_sparc_op_free(TestDetailSparcOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op->asi);
	cs_mem_free(op->membar_tag);
	cs_mem_free(op);
}

bool test_expected_sparc(csh *handle, const cs_sparc *actual,
			 const TestDetailSparc *expected)
{
	assert(handle && actual && expected);

	if (expected->cc) {
		compare_enum_ret(actual->cc, expected->cc, false);
	}
	if (expected->cc_field) {
		compare_enum_ret(actual->cc_field, expected->cc_field, false);
	}
	if (expected->hint) {
		compare_enum_ret(actual->hint, expected->hint, false);
	}

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);

	for (size_t i = 0; i < expected->operands_count; ++i) {
		const cs_sparc_op *op = &actual->operands[i];
		TestDetailSparcOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case SPARC_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case SPARC_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case SPARC_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
			compare_int32_ret(op->mem.disp, eop->mem_disp, false);
			break;
		case SPARC_OP_ASI:
			compare_enum_ret(op->asi, eop->asi, false);
			break;
		case SPARC_OP_MEMBAR_TAG:
			compare_enum_ret(op->membar_tag, eop->membar_tag,
					 false);
			break;
		}
	}

	return true;
}
