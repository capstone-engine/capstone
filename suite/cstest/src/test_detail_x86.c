// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_x86.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailX86 *test_detail_x86_new()
{
	return cs_mem_calloc(sizeof(TestDetailX86), 1);
}

void test_detail_x86_free(TestDetailX86 *detail)
{
	if (!detail) {
		return;
	}
	if (detail->prefix[0]) {
		for (size_t i = 0; i < ARR_SIZE(detail->prefix); ++i) {
			cs_mem_free(detail->prefix[i]);
		}
	}
	for (size_t i = 0; i < detail->eflags_count; ++i) {
		cs_mem_free(detail->eflags[i]);
	}
	cs_mem_free(detail->eflags);
	for (size_t i = 0; i < detail->fpu_flags_count; ++i) {
		cs_mem_free(detail->fpu_flags[i]);
	}
	cs_mem_free(detail->fpu_flags);
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_x86_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);

	cs_mem_free(detail->sib_index);
	cs_mem_free(detail->sib_base);
	cs_mem_free(detail->xop_cc);
	cs_mem_free(detail->sse_cc);
	cs_mem_free(detail->avx_cc);
	cs_mem_free(detail->avx_rm);
	cs_mem_free(detail);
}

TestDetailX86 *test_detail_x86_clone(TestDetailX86 *detail)
{
	TestDetailX86 *clone = test_detail_x86_new();
	clone->sib_index = detail->sib_index ? strdup(detail->sib_index) : NULL;
	clone->sib_base = detail->sib_base ? strdup(detail->sib_base) : NULL;
	clone->xop_cc = detail->xop_cc ? strdup(detail->xop_cc) : NULL;
	clone->sse_cc = detail->sse_cc ? strdup(detail->sse_cc) : NULL;
	clone->avx_cc = detail->avx_cc ? strdup(detail->avx_cc) : NULL;
	clone->avx_rm = detail->avx_rm ? strdup(detail->avx_rm) : NULL;

	if (detail->prefix[0]) {
		for (size_t i = 0; i < ARR_SIZE(clone->prefix); ++i) {
			clone->prefix[i] = strdup(detail->prefix[i]);
		}
	}
	memcpy(clone->opcode, detail->opcode, sizeof(clone->opcode));

	clone->rex = detail->rex;
	clone->addr_size = detail->addr_size;
	clone->modrm = detail->modrm;
	clone->sib = detail->sib;
	clone->disp = detail->disp;
	clone->sib_scale = detail->sib_scale;
	clone->avx_sae = detail->avx_sae;

	clone->enc_modrm_offset = detail->enc_modrm_offset;
	clone->enc_disp_offset = detail->enc_disp_offset;
	clone->enc_disp_size = detail->enc_disp_size;
	clone->enc_imm_offset = detail->enc_imm_offset;
	clone->enc_imm_size = detail->enc_imm_size;

	clone->eflags_count = detail->eflags_count;
	clone->eflags = detail->eflags ? cs_mem_calloc(sizeof(char *),
						       detail->eflags_count) :
					 NULL;
	for (size_t i = 0; clone->eflags && i < detail->eflags_count; ++i) {
		clone->eflags[i] =
			detail->eflags[i] ? strdup(detail->eflags[i]) : NULL;
	}

	clone->fpu_flags_count = detail->fpu_flags_count;
	clone->fpu_flags =
		detail->fpu_flags ?
			cs_mem_calloc(sizeof(char *), detail->fpu_flags_count) :
			NULL;
	for (size_t i = 0; clone->fpu_flags && i < detail->fpu_flags_count; ++i) {
		clone->fpu_flags[i] = detail->fpu_flags[i] ?
					      strdup(detail->fpu_flags[i]) :
					      NULL;
	}

	clone->operands_count = detail->operands_count;
	clone->operands = detail->operands_count > 0 ?
				  cs_mem_calloc(sizeof(TestDetailX86Op *),
						detail->operands_count) :
				  NULL;
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_x86_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailX86Op *test_detail_x86_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailX86Op), 1);
}

TestDetailX86Op *test_detail_x86_op_clone(TestDetailX86Op *op)
{
	TestDetailX86Op *clone = test_detail_x86_op_new();

	clone->size = op->size;
	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->mem_segment = op->mem_segment ? strdup(op->mem_segment) : NULL;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_index = op->mem_index ? strdup(op->mem_index) : NULL;
	clone->mem_scale = op->mem_scale;
	clone->mem_disp = op->mem_disp;
	clone->avx_bcast = op->avx_bcast ? strdup(op->avx_bcast) : NULL;
	clone->avx_zero_opmask = op->avx_zero_opmask;

	return clone;
}

void test_detail_x86_op_free(TestDetailX86Op *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_segment);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op->avx_bcast);
	cs_mem_free(op);
}

bool test_expected_x86(csh *handle, cs_x86 *actual, TestDetailX86 *expected)
{
	assert(handle && actual && expected);

	compare_reg_ret(*handle, actual->sib_index, expected->sib_index, false);
	compare_reg_ret(*handle, actual->sib_base, expected->sib_base, false);

	compare_enum_ret(actual->xop_cc, expected->xop_cc, false);
	compare_enum_ret(actual->sse_cc, expected->sse_cc, false);
	compare_enum_ret(actual->avx_cc, expected->avx_cc, false);
	compare_enum_ret(actual->avx_rm, expected->avx_rm, false);

	if (expected->rex) {
		compare_uint8_ret(actual->rex, expected->rex, false);
	}
	if (expected->addr_size) {
		compare_uint8_ret(actual->addr_size, expected->addr_size, false);
	}
	if (expected->modrm) {
		compare_uint8_ret(actual->modrm, expected->modrm, false);
	}
	if (expected->sib) {
		compare_uint8_ret(actual->sib, expected->sib, false);
	}
	if (expected->disp) {
		compare_int64_ret(actual->disp, expected->disp, false);
	}
	if (expected->sib_scale) {
		compare_int8_ret(actual->sib_scale, expected->sib_scale, false);
	}
	compare_tbool_ret(actual->avx_sae, expected->avx_sae, false);

	for (size_t i = 0; i < ARR_SIZE(actual->prefix); ++i) {
		compare_enum_ret(actual->prefix[i], expected->prefix[i],
				  false);
	}
	for (size_t i = 0; i < ARR_SIZE(actual->opcode); ++i) {
		if (expected->opcode[i] != 0) {
			compare_uint8_ret(actual->opcode[i], expected->opcode[i],
					  false);
		}
	}

	compare_bit_flags_64_ret(actual->eflags, expected->eflags,
				 expected->eflags_count, false);
	compare_bit_flags_64_ret(actual->fpu_flags, expected->fpu_flags,
				 expected->fpu_flags_count, false);

	if (expected->enc_modrm_offset) {
		compare_uint8_ret(actual->encoding.modrm_offset,
				  expected->enc_modrm_offset, false);
	}
	if (expected->enc_disp_offset) {
		compare_uint8_ret(actual->encoding.disp_offset,
				  expected->enc_disp_offset, false);
	}
	if (expected->enc_disp_size) {
		compare_uint8_ret(actual->encoding.disp_size,
				  expected->enc_disp_size, false);
	}
	if (expected->enc_imm_offset) {
		compare_uint8_ret(actual->encoding.imm_offset,
				  expected->enc_imm_offset, false);
	}
	if (expected->enc_imm_size) {
		compare_uint8_ret(actual->encoding.imm_size,
				  expected->enc_imm_size, false);
	}

	if (expected->operands_count == 0) {
		return true;
	}
	compare_uint8_ret(actual->op_count, expected->operands_count, false);

	for (size_t i = 0; i < actual->op_count; ++i) {
		cs_x86_op *op = &actual->operands[i];
		TestDetailX86Op *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		compare_enum_ret(op->avx_bcast, eop->avx_bcast, false);
		compare_tbool_ret(op->avx_zero_opmask, eop->avx_zero_opmask,
				  false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"arm op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case X86_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case X86_OP_IMM:
			compare_int64_ret(op->imm, eop->imm, false);
			break;
		case X86_OP_MEM:
			compare_reg_ret(*handle, op->mem.segment,
					eop->mem_segment, false);
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_reg_ret(*handle, op->mem.index, eop->mem_index,
					false);
			if (eop->mem_disp) {
				compare_int64_ret(op->mem.disp, eop->mem_disp, false);
			}
			if (eop->mem_scale) {
				compare_int_ret(op->mem.scale, eop->mem_scale,
						false);
			}
			break;
		}
	}

	return true;
}
