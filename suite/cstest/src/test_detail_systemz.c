// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_systemz.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailSystemZ *test_detail_systemz_new()
{
	return cs_mem_calloc(sizeof(TestDetailSystemZ), 1);
}

void test_detail_systemz_free(TestDetailSystemZ *detail)
{
	if (!detail) {
		return;
	}
	cs_mem_free(detail->format);
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_systemz_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailSystemZ *test_detail_systemz_clone(const TestDetailSystemZ *detail)
{
	TestDetailSystemZ *clone = test_detail_systemz_new();

	clone->format = detail->format ? strdup(detail->format) : NULL;
	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailSystemZOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_systemz_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailSystemZOp *test_detail_systemz_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailSystemZOp), 1);
}

TestDetailSystemZOp *test_detail_systemz_op_clone(const TestDetailSystemZOp *op)
{
	TestDetailSystemZOp *clone = test_detail_systemz_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->imm_width = op->imm_width;
	clone->mem_am = op->mem_am ? strdup(op->mem_am) : NULL;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->mem_disp = op->mem_disp;
	clone->mem_length = op->mem_length;

	return clone;
}

void test_detail_systemz_op_free(TestDetailSystemZOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_am);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op);
}

bool test_expected_systemz(csh *handle, const cs_systemz *actual,
			   const TestDetailSystemZ *expected)
{
	assert(handle && actual && expected);

	compare_enum_ret(actual->format, expected->format, false);
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_systemz_op *op = &actual->operands[i];
		TestDetailSystemZOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case SYSTEMZ_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case SYSTEMZ_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			compare_uint8_ret(op->imm_width, eop->imm_width, false);
			break;
		case SYSTEMZ_OP_MEM:
			compare_enum_ret(op->mem.am, eop->mem_am, false);
			switch(op->mem.am) {
			default:
				assert(0 && "Address mode not handled\n");
				break;
			case SYSTEMZ_AM_BD:
				compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
				compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
				break;
			case SYSTEMZ_AM_BDX:
			case SYSTEMZ_AM_BDV:
				compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
				compare_int64_ret(op->mem.disp, eop->mem_disp, false);
				compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
				break;
			case SYSTEMZ_AM_BDL:
				compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
				compare_int64_ret(op->mem.disp, eop->mem_disp, false);
				compare_uint64_ret(op->mem.length, eop->mem_length,
					   false);
				break;
			case SYSTEMZ_AM_BDR:
				compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
				compare_int64_ret(op->mem.disp, eop->mem_disp, false);
				compare_uint64_ret(op->mem.length, eop->mem_length,
					   false);
				break;
			}
			break;
		}
	}

	return true;
}
