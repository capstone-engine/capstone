// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_arm.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailARM *test_detail_arm_new()
{
	return cs_mem_calloc(sizeof(TestDetailARM), 1);
}

void test_detail_arm_free(TestDetailARM *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_arm_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->vector_data);
	cs_mem_free(detail->cps_mode);
	cs_mem_free(detail->cps_flag);
	cs_mem_free(detail->cc);
	cs_mem_free(detail->vcc);
	cs_mem_free(detail->mem_barrier);
	cs_mem_free(detail);
}

TestDetailARM *test_detail_arm_clone(TestDetailARM *detail)
{
	TestDetailARM *clone = test_detail_arm_new();
	clone->update_flags = detail->update_flags;
	clone->post_indexed = detail->post_indexed;
	clone->vector_data = detail->vector_data ? strdup(detail->vector_data) : NULL;
	clone->cps_mode = detail->cps_mode ? strdup(detail->cps_mode) : NULL;
	clone->cps_flag = detail->cps_flag ? strdup(detail->cps_flag) : NULL;
	clone->cc = detail->cc ? strdup(detail->cc) : NULL;
	clone->vcc = detail->vcc ? strdup(detail->vcc) : NULL;
	clone->mem_barrier = detail->mem_barrier ? strdup(detail->mem_barrier) : NULL;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailARMOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_arm_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailARMOp *test_detail_arm_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailARMOp), 1);
}

TestDetailARMOp *test_detail_arm_op_clone(TestDetailARMOp *op)
{
	TestDetailARMOp *clone = test_detail_arm_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->setend = op->setend ? strdup(op->setend) : NULL;
	clone->pred = op->pred;
	clone->fp = op->fp;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->mem_scale = op->mem_scale;
	clone->mem_disp = op->mem_disp;
	clone->mem_align = op->mem_align;
	clone->sys_reg = op->sys_reg ? strdup(op->sys_reg) : NULL;
	clone->sys_psr_bits_count = op->sys_psr_bits_count;
	clone->sys_psr_bits =
		op->sys_psr_bits_count == 0 ?
			NULL :
			cs_mem_calloc(sizeof(char *), op->sys_psr_bits_count);
	for (size_t i = 0; i < op->sys_psr_bits_count; ++i) {
		clone->sys_psr_bits[i] = strdup(op->sys_psr_bits[i]);
	}
	clone->sys_sysm = op->sys_sysm;
	clone->sys_msr_mask = op->sys_msr_mask;
	clone->shift_type = op->shift_type ? strdup(op->shift_type) : NULL;
	clone->shift_value = op->shift_value;
	clone->neon_lane = op->neon_lane;
	clone->vector_index = op->vector_index;
	clone->vector_index_is_set = op->vector_index_is_set;
	clone->subtracted = op->subtracted;

	return clone;
}

void test_detail_arm_op_free(TestDetailARMOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->setend);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op->shift_type);
	cs_mem_free(op->sys_reg);
	if (op->sys_psr_bits_count != 0) {
		for (size_t i = 0; i < op->sys_psr_bits_count; ++i) {
			cs_mem_free(op->sys_psr_bits[i]);
		}
		cs_mem_free(op->sys_psr_bits);
	}
	cs_mem_free(op);
}

bool test_expected_arm(csh *handle, cs_arm *actual, TestDetailARM *expected)
{
	assert(handle && actual && expected);

	if (expected->vector_size) {
		compare_int_ret(actual->vector_size, expected->vector_size,
				false);
	}
	compare_enum_ret(actual->vector_data, expected->vector_data, false);
	compare_enum_ret(actual->cps_flag, expected->cps_flag, false);
	compare_enum_ret(actual->cps_mode, expected->cps_mode, false);
	compare_enum_ret(actual->cc, expected->cc, false);
	compare_enum_ret(actual->vcc, expected->vcc, false);
	compare_enum_ret(actual->mem_barrier, expected->mem_barrier, false);
	if (expected->pred_mask) {
		compare_uint8_ret(actual->pred_mask, expected->pred_mask,
				  false);
	}
	compare_tbool_ret(actual->usermode, expected->usermode, false);
	compare_tbool_ret(actual->update_flags, expected->update_flags, false);
	compare_tbool_ret(actual->post_index, expected->post_indexed, false);

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_arm_op *op = &actual->operands[i];
		TestDetailARMOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case ARM_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case ARM_OP_IMM:
		case ARM_OP_PIMM:
		case ARM_OP_CIMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case ARM_OP_PRED:
			compare_int_ret(op->pred, eop->pred, false);
			break;
		case ARM_OP_SETEND:
			compare_enum_ret(op->setend, eop->setend, false);
			break;
		case ARM_OP_FP:
			compare_fp_ret(op->fp, eop->fp, false);
			break;
		case ARM_OP_SYSREG:
			compare_enum_ret(op->sysop.reg.mclasssysreg,
					 eop->sys_reg, false);
			if (eop->sys_sysm) {
				compare_uint16_ret(op->sysop.sysm,
						   eop->sys_sysm, false);
			}
			if (eop->sys_msr_mask) {
				compare_uint8_ret(op->sysop.msr_mask,
						  eop->sys_msr_mask, false);
			}
			break;
		case ARM_OP_BANKEDREG:
			compare_enum_ret(op->sysop.reg.bankedreg, eop->sys_reg,
					 false);
			if (eop->sys_sysm) {
				compare_uint16_ret(op->sysop.sysm,
						   eop->sys_sysm, false);
			}
			if (eop->sys_msr_mask) {
				compare_uint8_ret(op->sysop.msr_mask,
						  eop->sys_msr_mask, false);
			}
			break;
		case ARM_OP_SPSR:
		case ARM_OP_CPSR:
			compare_bit_flags_ret(op->sysop.psr_bits,
					      eop->sys_psr_bits,
					      eop->sys_psr_bits_count, false);
			if (eop->sys_sysm) {
				compare_uint16_ret(op->sysop.sysm,
						   eop->sys_sysm, false);
			}
			if (eop->sys_msr_mask) {
				compare_uint8_ret(op->sysop.msr_mask,
						  eop->sys_msr_mask, false);
			}
			break;
		case ARM_OP_SYSM:
			if (eop->sys_sysm) {
				compare_uint16_ret(op->sysop.sysm,
						   eop->sys_sysm, false);
			}
			if (eop->sys_msr_mask) {
				compare_uint8_ret(op->sysop.msr_mask,
						  eop->sys_msr_mask, false);
			}
			break;
		case ARM_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
			compare_int_ret(op->mem.disp, eop->mem_disp, false);
			compare_uint_ret(op->mem.align, eop->mem_align, false);
			if (eop->mem_scale) {
				compare_int_ret(op->mem.scale, eop->mem_scale, false);
			}
			break;
		}

		compare_enum_ret(op->shift.type, eop->shift_type, false);
		if (eop->shift_value) {
			compare_uint32_ret(op->shift.value, eop->shift_value,
					   false);
		}
		if (eop->neon_lane) {
			compare_uint8_ret(op->neon_lane, eop->neon_lane, false);
		}

		if (eop->vector_index_is_set) {
			compare_int32_ret(op->vector_index, eop->vector_index,
					  false);
		} else {
			assert(eop->vector_index == 0);
		}
		compare_tbool_ret(op->subtracted, eop->subtracted, false);
	}

	return true;
}
