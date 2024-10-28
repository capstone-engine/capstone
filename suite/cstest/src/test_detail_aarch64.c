// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_aarch64.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailAArch64 *test_detail_aarch64_new()
{
	return cs_mem_calloc(sizeof(TestDetailAArch64), 1);
}

void test_detail_aarch64_free(TestDetailAArch64 *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_aarch64_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->cc);
	cs_mem_free(detail);
}

TestDetailAArch64 *test_detail_aarch64_clone(TestDetailAArch64 *detail)
{
	TestDetailAArch64 *clone = test_detail_aarch64_new();
	clone->cc = detail->cc ? strdup(detail->cc) : NULL;
	clone->update_flags = detail->update_flags;
	clone->post_indexed = detail->post_indexed;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailAArch64Op *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_aarch64_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailAArch64Op *test_detail_aarch64_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailAArch64Op), 1);
}

TestDetailAArch64Op *test_detail_aarch64_op_clone(TestDetailAArch64Op *op)
{
	TestDetailAArch64Op *clone = test_detail_aarch64_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->sub_type = op->sub_type ? strdup(op->sub_type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->shift_type = op->shift_type ? strdup(op->shift_type) : NULL;
	clone->ext = op->ext ? strdup(op->ext) : NULL;
	clone->vas = op->vas ? strdup(op->vas) : NULL;
	clone->imm = op->imm;
	clone->sme = op->sme ? test_detail_aarch64_op_sme_clone(op->sme) : NULL;
	clone->pred_reg = op->pred_reg ? strdup(op->pred_reg) : NULL;
	clone->pred_vec_select =
		op->pred_vec_select ? strdup(op->pred_vec_select) : NULL;
	clone->pred_imm_index = op->pred_imm_index;
	clone->pred_imm_index_set = op->pred_imm_index_set;
	clone->mem_disp = op->mem_disp;
	clone->imm_range_first = op->imm_range_first;
	clone->imm_range_offset = op->imm_range_offset;
	clone->fp = op->fp;
	clone->fp_set = op->fp_set;
	clone->sys_raw_val = op->sys_raw_val;
	clone->shift_value = op->shift_value;
	clone->is_vreg = op->is_vreg;
	clone->vector_index = op->vector_index;
	clone->vector_index_is_set = op->vector_index_is_set;
	clone->is_list_member = op->is_list_member;

	return clone;
}

void test_detail_aarch64_op_free(TestDetailAArch64Op *op)
{
	if (!op) {
		return;
	}
	test_detail_aarch64_op_sme_free(op->sme);
	cs_mem_free(op->type);
	cs_mem_free(op->sub_type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op->shift_type);
	cs_mem_free(op->ext);
	cs_mem_free(op->vas);
	cs_mem_free(op->pred_reg);
	cs_mem_free(op->pred_vec_select);
	cs_mem_free(op);
}

TestDetailAArch64SME *test_detail_aarch64_op_sme_new()
{
	return cs_mem_calloc(sizeof(TestDetailAArch64SME), 1);
}

TestDetailAArch64SME *test_detail_aarch64_op_sme_clone(TestDetailAArch64SME *sme)
{
	TestDetailAArch64SME *clone = test_detail_aarch64_op_sme_new();

	clone->type = sme->type ? strdup(sme->type) : NULL;
	clone->tile = sme->tile ? strdup(sme->tile) : NULL;
	clone->slice_reg = sme->slice_reg ? strdup(sme->slice_reg) : NULL;
	clone->slice_offset_imm = sme->slice_offset_imm;
	clone->slice_offset_ir_first = sme->slice_offset_ir_first;
	clone->slice_offset_ir_offset = sme->slice_offset_ir_offset;
	clone->slice_offset_ir_set = sme->slice_offset_ir_set;
	clone->has_range_offset = sme->has_range_offset;
	clone->is_vertical = sme->is_vertical;

	return clone;
}

void test_detail_aarch64_op_sme_free(TestDetailAArch64SME *sme)
{
	if (!sme) {
		return;
	}
	cs_mem_free(sme->type);
	cs_mem_free(sme->tile);
	cs_mem_free(sme->slice_reg);
	cs_mem_free(sme);
}

bool test_expected_aarch64(csh *handle, cs_aarch64 *actual,
			   TestDetailAArch64 *expected)
{
	assert(handle && actual && expected);

	compare_enum_ret(actual->cc, expected->cc, false);
	compare_tbool_ret(actual->update_flags, expected->update_flags, false);
	compare_tbool_ret(actual->post_index, expected->post_indexed, false);

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_aarch64_op *op = &actual->operands[i];
		TestDetailAArch64Op *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"AArch64 op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case AARCH64_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case AARCH64_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case AARCH64_OP_IMM_RANGE:
			compare_int8_ret(op->imm_range.first,
					 eop->imm_range_first, false);
			compare_int8_ret(op->imm_range.offset,
					 eop->imm_range_offset, false);
			break;
		case AARCH64_OP_FP:
			compare_fp_ret(op->fp, eop->fp, false);
			break;
		case AARCH64_OP_SYSREG:
			compare_enum_ret(op->sysop.sub_type, eop->sub_type,
					 false);
			compare_int_ret(op->sysop.reg.raw_val,
					   eop->sys_raw_val, false);
			break;
		case AARCH64_OP_SYSIMM:
			compare_enum_ret(op->sysop.sub_type, eop->sub_type,
					 false);
			compare_int_ret(op->sysop.imm.raw_val,
					   eop->sys_raw_val, false);
			if (eop->fp_set) {
				compare_fp_ret(op->fp, eop->fp, false);
			}
			break;
		case AARCH64_OP_SYSALIAS:
			compare_enum_ret(op->sysop.sub_type, eop->sub_type,
					 false);
			compare_int_ret(op->sysop.alias.raw_val,
					   eop->sys_raw_val, false);
			break;
		case AARCH64_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
			compare_int32_ret(op->mem.disp, eop->mem_disp, false);
			break;
		case AARCH64_OP_PRED:
			compare_reg_ret(*handle, op->pred.reg, eop->pred_reg,
					false);
			compare_reg_ret(*handle, op->pred.vec_select, eop->pred_vec_select,
					false);
			if (eop->pred_imm_index_set) {
				compare_int32_ret(op->pred.imm_index, eop->pred_imm_index, false);
			} else {
				assert(eop->pred_imm_index == 0);
			}
			break;
		case AARCH64_OP_SME:
			compare_enum_ret(op->sme.type, eop->sme->type,
					false);
			compare_reg_ret(*handle, op->sme.tile, eop->sme->tile,
					false);
			compare_reg_ret(*handle, op->sme.slice_reg, eop->sme->slice_reg,
					false);
			compare_tbool_ret(op->sme.has_range_offset, eop->sme->has_range_offset,
					false);
			compare_tbool_ret(op->sme.is_vertical, eop->sme->is_vertical,
					false);
			if (eop->sme->slice_offset_imm) {
				compare_int32_ret(op->sme.slice_offset.imm, eop->sme->slice_offset_imm, false);
			}
			if (eop->sme->slice_offset_ir_set) {
				compare_int32_ret(op->sme.slice_offset.imm_range.first, eop->sme->slice_offset_ir_first, false);
				compare_int32_ret(op->sme.slice_offset.imm_range.offset, eop->sme->slice_offset_ir_offset, false);
			} else {
				assert(eop->sme->slice_offset_ir_first == 0 && eop->sme->slice_offset_ir_offset == 0);
			}
			break;
		}

		compare_enum_ret(op->shift.type, eop->shift_type, false);
		compare_uint32_ret(op->shift.value, eop->shift_value, false);
		compare_enum_ret(op->ext, eop->ext, false);

		compare_enum_ret(op->vas, eop->vas, false);
		compare_tbool_ret(op->is_vreg, eop->is_vreg, false);
		if (eop->vector_index_is_set) {
			compare_int32_ret(op->vector_index, eop->vector_index,
					  false);
		} else {
			assert(eop->vector_index == 0);
		}

		compare_tbool_ret(op->is_list_member, eop->is_list_member,
				  false);
	}

	return true;
}
