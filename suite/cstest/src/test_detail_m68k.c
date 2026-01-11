// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "capstone/m68k.h"
#include "test_compare.h"
#include "test_detail_m68k.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailM68KOpMem *test_detail_m68k_op_mem_new()
{
	return cs_mem_calloc(sizeof(TestDetailM68KOpMem), 1);
}

TestDetailM68KOpMem *test_detail_m68k_op_mem_clone(TestDetailM68KOpMem *mem)
{
	assert(mem);
	TestDetailM68KOpMem *clone = test_detail_m68k_op_mem_new();

	clone->base_reg = mem->base_reg ? strdup(mem->base_reg) : NULL;
	clone->index_reg = mem->index_reg ? strdup(mem->index_reg) : NULL;
	clone->in_base_reg = mem->in_base_reg ? strdup(mem->in_base_reg) : NULL;
	clone->index_size = mem->index_size;
	clone->disp = mem->disp;
	clone->in_disp = mem->in_disp;
	clone->out_disp = mem->out_disp;
	clone->scale = mem->scale;
	clone->bitfield = mem->bitfield;
	clone->width = mem->width;
	clone->offset = mem->offset;
	clone->in_disp_size = mem->in_disp_size;
	clone->out_disp_size = mem->out_disp_size;
	clone->disp_size = mem->disp_size;

	return clone;
}

void test_detail_m68k_op_mem_free(TestDetailM68KOpMem *mem)
{
	if (!mem) {
		return;
	}
	cs_mem_free(mem->base_reg);
	cs_mem_free(mem->index_reg);
	cs_mem_free(mem->in_base_reg);
	cs_mem_free(mem);
}

TestDetailM68K *test_detail_m68k_new()
{
	return cs_mem_calloc(sizeof(TestDetailM68K), 1);
}

void test_detail_m68k_free(TestDetailM68K *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_m68k_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail->op_size_type);
	cs_mem_free(detail->op_size_fpu);
	cs_mem_free(detail->op_size_cpu);
	cs_mem_free(detail);
}

TestDetailM68K *test_detail_m68k_clone(TestDetailM68K *detail)
{
	TestDetailM68K *clone = test_detail_m68k_new();
	clone->op_size_type =
		detail->op_size_type ? strdup(detail->op_size_type) : NULL;
	clone->op_size_fpu = detail->op_size_fpu ? strdup(detail->op_size_fpu) :
						   NULL;
	clone->op_size_cpu = detail->op_size_cpu ? strdup(detail->op_size_cpu) :
						   NULL;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailM68KOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_m68k_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailM68KOp *test_detail_m68k_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailM68KOp), 1);
}

TestDetailM68KOp *test_detail_m68k_op_clone(TestDetailM68KOp *op)
{
	TestDetailM68KOp *clone = test_detail_m68k_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->reg_pair_0 = op->reg_pair_0 ? strdup(op->reg_pair_0) : NULL;
	clone->reg_pair_1 = op->reg_pair_1 ? strdup(op->reg_pair_1) : NULL;
	clone->address_mode = op->address_mode ? strdup(op->address_mode) :
						 NULL;

	clone->imm = op->imm;
	clone->dimm = op->dimm;
	clone->simm = op->simm;
	clone->br_disp = op->br_disp;
	clone->br_disp_size = op->br_disp_size;
	clone->register_bits = op->register_bits;

	clone->mem = op->mem ? test_detail_m68k_op_mem_clone(op->mem) : NULL;
	return clone;
}

void test_detail_m68k_op_free(TestDetailM68KOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->reg);
	cs_mem_free(op->reg_pair_0);
	cs_mem_free(op->reg_pair_1);
	cs_mem_free(op->address_mode);
	test_detail_m68k_op_mem_free(op->mem);
	cs_mem_free(op);
}

bool test_expected_m68k(csh *handle, cs_m68k *actual, TestDetailM68K *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	compare_enum_ret(actual->op_size.type, expected->op_size_type, false);
	compare_enum_ret(actual->op_size.fpu_size, expected->op_size_fpu,
			 false);
	compare_enum_ret(actual->op_size.cpu_size, expected->op_size_cpu,
			 false);

	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_m68k_op *op = &actual->operands[i];
		TestDetailM68KOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->address_mode, eop->address_mode, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"M68K op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case M68K_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case M68K_OP_REG_PAIR:
			compare_reg_ret(*handle, op->reg_pair.reg_0,
					eop->reg_pair_0, false);
			compare_reg_ret(*handle, op->reg_pair.reg_1,
					eop->reg_pair_1, false);
			break;
		case M68K_OP_IMM:
			compare_uint64_ret(op->imm, eop->imm, false);
			break;
		case M68K_OP_FP_SINGLE:
			compare_fp_ret(op->simm, eop->simm, false);
			break;
		case M68K_OP_FP_DOUBLE:
			compare_fp_ret(op->dimm, eop->dimm, false);
			break;
		case M68K_OP_REG_BITS:
			compare_uint32_ret(op->register_bits,
					   eop->register_bits, false);
			break;
		case M68K_OP_BR_DISP:
			compare_int32_ret(op->br_disp.disp, eop->br_disp,
					  false);
			compare_uint8_ret(op->br_disp.disp_size,
					  eop->br_disp_size, false);
			break;
		case M68K_OP_MEM:
			if (!eop->mem) {
				break;
			}
			compare_reg_ret(*handle, op->mem.base_reg,
					eop->mem->base_reg, false);
			compare_reg_ret(*handle, op->mem.index_reg,
					eop->mem->index_reg, false);
			compare_reg_ret(*handle, op->mem.in_base_reg,
					eop->mem->in_base_reg, false);
			compare_tbool_ret(op->mem.index_size,
					  eop->mem->index_size, false);
			if (eop->mem->in_disp) {
				compare_int32_ret(op->mem.in_disp,
						  eop->mem->in_disp, false);
			}
			if (eop->mem->out_disp) {
				compare_int32_ret(op->mem.out_disp,
						  eop->mem->out_disp, false);
			}
			if (eop->mem->disp) {
				compare_int16_ret(op->mem.disp, eop->mem->disp,
						  false);
			}
			if (eop->mem->scale) {
				compare_uint8_ret(op->mem.scale,
						  eop->mem->scale, false);
			}
			if (eop->mem->bitfield) {
				compare_uint8_ret(op->mem.bitfield,
						  eop->mem->bitfield, false);
			}
			if (eop->mem->width) {
				compare_uint8_ret(op->mem.width,
						  eop->mem->width, false);
			}
			if (eop->mem->offset) {
				compare_uint8_ret(op->mem.offset,
						  eop->mem->offset, false);
			}
			compare_tbool_ret(op->mem.in_disp_size,
					  eop->mem->in_disp_size, false);
			compare_tbool_ret(op->mem.out_disp_size,
					  eop->mem->out_disp_size, false);
			compare_tbool_ret(op->mem.disp_size,
					  eop->mem->disp_size, false);
			break;
		}
	}

	return true;
}
