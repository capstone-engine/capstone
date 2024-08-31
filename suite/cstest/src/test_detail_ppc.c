// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_ppc.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailPPCBC *test_detail_ppc_bc_new()
{
	return cs_mem_calloc(sizeof(TestDetailPPCBC), 1);
}

TestDetailPPCBC *test_detail_ppc_bc_clone(const TestDetailPPCBC *bc)
{
	assert(bc);
	TestDetailPPCBC *clone = test_detail_ppc_bc_new();
	clone->bh = bc->bh ? strdup(bc->bh) : NULL;
	clone->crX = bc->crX ? strdup(bc->crX) : NULL;
	clone->crX_bit = bc->crX_bit ? strdup(bc->crX_bit) : NULL;
	clone->hint = bc->hint ? strdup(bc->hint) : NULL;
	clone->pred_cr = bc->pred_cr ? strdup(bc->pred_cr) : NULL;
	clone->pred_ctr = bc->pred_ctr ? strdup(bc->pred_ctr) : NULL;
	clone->bi = bc->bi;
	clone->bi_set = bc->bi_set;
	clone->bo = bc->bo;
	clone->bo_set = bc->bo_set;
	return clone;
}

void test_detail_ppc_bc_free(TestDetailPPCBC *bc)
{
	if (!bc) {
		return;
	}
	cs_mem_free(bc->bh);
	cs_mem_free(bc->crX);
	cs_mem_free(bc->crX_bit);
	cs_mem_free(bc->hint);
	cs_mem_free(bc->pred_cr);
	cs_mem_free(bc->pred_ctr);
	cs_mem_free(bc);
}

TestDetailPPC *test_detail_ppc_new()
{
	return cs_mem_calloc(sizeof(TestDetailPPC), 1);
}

void test_detail_ppc_free(TestDetailPPC *detail)
{
	if (!detail) {
		return;
	}
	test_detail_ppc_bc_free(detail->bc);
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_ppc_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->format);
	cs_mem_free(detail);
}

TestDetailPPC *test_detail_ppc_clone(const TestDetailPPC *detail)
{
	TestDetailPPC *clone = test_detail_ppc_new();
	clone->format = detail->format ? strdup(detail->format) : NULL;
	clone->update_cr0 = detail->update_cr0;
	clone->bc = detail->bc ? test_detail_ppc_bc_clone(detail->bc) : NULL;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailPPCOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_ppc_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailPPCOp *test_detail_ppc_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailPPCOp), 1);
}

TestDetailPPCOp *test_detail_ppc_op_clone(const TestDetailPPCOp *op)
{
	TestDetailPPCOp *clone = test_detail_ppc_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_offset = op->mem_offset ? strdup(op->mem_offset) : NULL;
	clone->mem_disp = op->mem_disp;

	return clone;
}

void test_detail_ppc_op_free(TestDetailPPCOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_offset);
	cs_mem_free(op);
}

bool test_expected_ppc(csh *handle, const cs_ppc *actual,
		       const TestDetailPPC *expected)
{
	assert(handle && actual && expected);

	compare_enum_ret(actual->format, expected->format, false);
	compare_tbool_ret(actual->update_cr0, expected->update_cr0, false);

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_ppc_op *op = &actual->operands[i];
		TestDetailPPCOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case PPC_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case PPC_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case PPC_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.offset,
					eop->mem_offset, false);
			compare_int_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}

		if (expected->bc) {
			if (expected->bc->bi_set) {
				compare_uint8_ret(actual->bc.bi,
						  expected->bc->bi, false);
			} else {
				assert(expected->bc->bi == 0);
			}
			if (expected->bc->bo_set) {
				compare_uint8_ret(actual->bc.bo,
						  expected->bc->bo, false);
			} else {
				assert(expected->bc->bo == 0);
			}
			compare_enum_ret(actual->bc.bh, expected->bc->bh,
					 false);
			compare_reg_ret(*handle, actual->bc.crX,
					expected->bc->crX, false);
			compare_enum_ret(actual->bc.crX_bit,
					 expected->bc->crX_bit, false);
			compare_enum_ret(actual->bc.hint, expected->bc->hint,
					 false);
			compare_enum_ret(actual->bc.pred_cr,
					 expected->bc->pred_cr, false);
			compare_enum_ret(actual->bc.pred_ctr,
					 expected->bc->pred_ctr, false);
		}
	}

	return true;
}
