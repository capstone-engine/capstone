// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "capstone/tms320c64x.h"
#include "test_compare.h"
#include "test_detail_tms320c64x.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailTMS320c64x *test_detail_tms320c64x_new()
{
	return cs_mem_calloc(sizeof(TestDetailTMS320c64x), 1);
}

void test_detail_tms320c64x_free(TestDetailTMS320c64x *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_tms320c64x_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->cond_reg);
	cs_mem_free(detail->funit_unit);
	cs_mem_free(detail);
}

TestDetailTMS320c64x *test_detail_tms320c64x_clone(TestDetailTMS320c64x *detail)
{
	TestDetailTMS320c64x *clone = test_detail_tms320c64x_new();
	clone->cond_reg = detail->cond_reg ? strdup(detail->cond_reg) : NULL;
	clone->cond_zero = detail->cond_zero;
	clone->funit_unit = detail->funit_unit ? strdup(detail->funit_unit) :
						 NULL;
	clone->funit_side = detail->funit_side;
	clone->funit_side_set = detail->funit_side_set;
	clone->funit_crosspath = detail->funit_crosspath;
	clone->funit_crosspath_set = detail->funit_crosspath_set;

	clone->parallel = detail->parallel;
	clone->parallel_set = detail->parallel_set;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands =
			cs_mem_calloc(sizeof(TestDetailTMS320c64xOp *),
				      detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_tms320c64x_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailTMS320c64xOp *test_detail_tms320c64x_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailTMS320c64xOp), 1);
}

TestDetailTMS320c64xOp *
test_detail_tms320c64x_op_clone(TestDetailTMS320c64xOp *op)
{
	TestDetailTMS320c64xOp *clone = test_detail_tms320c64x_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->reg_pair_0 = op->reg_pair_0 ? strdup(op->reg_pair_0) : NULL;
	clone->reg_pair_1 = op->reg_pair_1 ? strdup(op->reg_pair_1) : NULL;
	clone->imm = op->imm;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_scaled = op->mem_scaled;
	clone->mem_disptype = op->mem_disptype ? strdup(op->mem_disptype) :
						 NULL;
	clone->mem_direction = op->mem_direction ? strdup(op->mem_direction) :
						   NULL;
	clone->mem_modify = op->mem_modify ? strdup(op->mem_modify) : NULL;
	clone->mem_disp_const = op->mem_disp_const;
	clone->mem_disp_reg = op->mem_disp_reg ? strdup(op->mem_disp_reg) :
						 NULL;
	clone->mem_unit = op->mem_unit;

	return clone;
}

void test_detail_tms320c64x_op_free(TestDetailTMS320c64xOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_disp_reg);
	cs_mem_free(op->mem_disptype);
	cs_mem_free(op->mem_direction);
	cs_mem_free(op->mem_modify);
	cs_mem_free(op->reg);
	cs_mem_free(op->reg_pair_0);
	cs_mem_free(op->reg_pair_1);
	cs_mem_free(op);
}

bool test_expected_tms320c64x(csh *handle, cs_tms320c64x *actual,
			      TestDetailTMS320c64x *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	compare_reg_ret(*handle, actual->condition.reg, expected->cond_reg,
			false);
	compare_tbool_ret(actual->condition.zero, expected->cond_zero, false);
	compare_enum_ret(actual->funit.unit, expected->funit_unit, false);
	if (expected->funit_side_set) {
		compare_uint8_ret(actual->funit.side, expected->funit_side,
				  false);
	} else {
		assert(expected->funit_side == 0);
	}
	if (expected->funit_crosspath_set) {
		compare_uint8_ret(actual->funit.crosspath,
				  expected->funit_crosspath, false);
	} else {
		assert(expected->funit_crosspath == 0);
	}
	if (expected->parallel_set) {
		compare_uint8_ret(actual->parallel, expected->parallel, false);
	} else {
		assert(expected->parallel == 0);
	}
	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_tms320c64x_op *op = &actual->operands[i];
		TestDetailTMS320c64xOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"tms320c64x op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case TMS320C64X_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case TMS320C64X_OP_REGPAIR:
			compare_reg_ret(*handle, op->reg + 1, eop->reg_pair_0,
					false);
			compare_reg_ret(*handle, op->reg, eop->reg_pair_1,
					false);
			break;
		case TMS320C64X_OP_IMM:
			compare_int32_ret(op->imm, eop->imm, false);
			break;
		case TMS320C64X_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_enum_ret(op->mem.direction, eop->mem_direction,
					 false);
			compare_tbool_ret(op->mem.scaled, eop->mem_scaled,
					  false);
			compare_enum_ret(op->mem.disptype, eop->mem_disptype,
					 false);
			if (op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
				compare_reg_ret(*handle, op->mem.disp,
						eop->mem_disp_reg, false);
			} else {
				compare_uint_ret(op->mem.disp,
						 eop->mem_disp_const, false);
			}
			compare_enum_ret(op->mem.modify, eop->mem_modify,
					 false);
			compare_uint_ret(op->mem.unit, eop->mem_unit, false);
			break;
		}
	}

	return true;
}
