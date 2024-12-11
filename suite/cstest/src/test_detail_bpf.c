// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_bpf.h"
#include <capstone/bpf.h>
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailBPF *test_detail_bpf_new()
{
	return cs_mem_calloc(sizeof(TestDetailBPF), 1);
}

void test_detail_bpf_free(TestDetailBPF *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_bpf_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailBPF *test_detail_bpf_clone(const TestDetailBPF *detail)
{
	TestDetailBPF *clone = test_detail_bpf_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailBPFOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_bpf_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailBPFOp *test_detail_bpf_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailBPFOp), 1);
}

TestDetailBPFOp *test_detail_bpf_op_clone(const TestDetailBPFOp *op)
{
	TestDetailBPFOp *clone = test_detail_bpf_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->imm = op->imm;
	clone->off = op->off;
	clone->mmem = op->mmem;
	clone->msh = op->msh;
	clone->ext = op->ext ? strdup(op->ext) : NULL;
	clone->mem_base = op->mem_base ? strdup(op->mem_base) : NULL;
	clone->mem_disp = op->mem_disp;
	clone->is_pkt = op->is_pkt;
	clone->is_signed = op->is_signed;

	return clone;
}

void test_detail_bpf_op_free(TestDetailBPFOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->ext);
	cs_mem_free(op->mem_base);
	cs_mem_free(op);
}

bool test_expected_bpf(csh *handle, const cs_bpf *actual,
		       const TestDetailBPF *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_bpf_op *op = &actual->operands[i];
		TestDetailBPFOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		compare_tbool_ret(op->is_pkt, eop->is_pkt, false);
		compare_tbool_ret(op->is_signed, eop->is_signed, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"bpf op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case BPF_OP_REG:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case BPF_OP_IMM:
			compare_uint64_ret(op->imm, eop->imm, false);
			break;
		case BPF_OP_OFF:
			compare_uint32_ret(op->off, eop->off, false);
			break;
		case BPF_OP_MMEM:
			compare_uint32_ret(op->mmem, eop->mmem, false);
			break;
		case BPF_OP_MSH:
			compare_uint32_ret(op->msh, eop->msh, false);
			break;
		case BPF_OP_EXT:
			compare_enum_ret(op->ext, eop->ext, false);
			break;
		case BPF_OP_MEM:
			compare_reg_ret(*handle, op->mem.base, eop->mem_base,
					false);
			compare_uint32_ret(op->mem.disp, eop->mem_disp, false);
			break;
		}
	}

	return true;
}
