// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_m680x.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailM680xIdx *test_detail_m680x_idx_new()
{
	return cs_mem_calloc(sizeof(TestDetailM680xIdx), 1);
}

TestDetailM680xIdx *test_detail_m680x_idx_clone(const TestDetailM680xIdx *idx)
{
	assert(idx);
	TestDetailM680xIdx *clone = test_detail_m680x_idx_new();
	clone->base_reg = idx->base_reg ? strdup(idx->base_reg) : NULL;
	clone->offset_reg = idx->offset_reg ? strdup(idx->offset_reg) : NULL;
	clone->flags = idx->flags_count > 0 ?
			       cs_mem_calloc(sizeof(char *), idx->flags_count) :
			       NULL;
	clone->flags_count = idx->flags_count;
	for (size_t i = 0; i < clone->flags_count; ++i) {
		clone->flags[i] = idx->flags[i] ? strdup(idx->flags[i]) : NULL;
	}
	clone->offset = idx->offset;
	clone->offset_addr = idx->offset_addr;
	clone->offset_bits = idx->offset_bits;
	clone->inc_dec = idx->inc_dec;
	return clone;
}

void test_detail_m680x_idx_free(TestDetailM680xIdx *idx)
{
	if (!idx) {
		return;
	}
	cs_mem_free(idx->base_reg);
	cs_mem_free(idx->offset_reg);
	for (size_t i = 0; i < idx->flags_count; ++i) {
		cs_mem_free(idx->flags[i]);
	}
	cs_mem_free(idx->flags);
	cs_mem_free(idx);
}

TestDetailM680x *test_detail_m680x_new()
{
	return cs_mem_calloc(sizeof(TestDetailM680x), 1);
}

void test_detail_m680x_free(TestDetailM680x *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_m680x_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	for (size_t i = 0; i < detail->flags_count; ++i) {
		cs_mem_free(detail->flags[i]);
	}
	cs_mem_free(detail->flags);
	cs_mem_free(detail);
}

TestDetailM680x *test_detail_m680x_clone(const TestDetailM680x *detail)
{
	TestDetailM680x *clone = test_detail_m680x_new();

	clone->flags_count = detail->flags_count;
	if (detail->flags_count > 0) {
		clone->flags =
			cs_mem_calloc(sizeof(char *), detail->flags_count);
	}
	for (size_t i = 0; i < detail->flags_count; ++i) {
		clone->flags[i] = detail->flags[i] ? strdup(detail->flags[i]) :
						     NULL;
	}
	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailM680xOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_m680x_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailM680xOp *test_detail_m680x_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailM680xOp), 1);
}

TestDetailM680xOp *test_detail_m680x_op_clone(const TestDetailM680xOp *op)
{
	TestDetailM680xOp *clone = test_detail_m680x_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->access = op->access ? strdup(op->access) : NULL;
	clone->reg = op->reg ? strdup(op->reg) : NULL;
	clone->idx = op->idx ? test_detail_m680x_idx_clone(op->idx) : NULL;
	clone->imm = op->imm;
	clone->rel_address = op->rel_address;
	clone->rel_offset = op->rel_offset;
	clone->ext_address = op->ext_address;
	clone->ext_indirect = op->ext_indirect;
	clone->direct_addr = op->direct_addr;
	clone->direct_addr_set = op->direct_addr_set;
	clone->const_val = op->const_val;
	clone->size = op->size;

	return clone;
}

void test_detail_m680x_op_free(TestDetailM680xOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	test_detail_m680x_idx_free(op->idx);
	cs_mem_free(op);
}

bool test_expected_m680x(csh *handle, const cs_m680x *actual,
			 const TestDetailM680x *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_m680x_op *op = &actual->operands[i];
		TestDetailM680xOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		compare_enum_ret(op->access, eop->access, false);
		if (eop->size > 0) {
			compare_uint8_ret(op->size, eop->size, false);
		}
		switch (op->type) {
		default:
			fprintf(stderr,
				"m680x op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case M680X_OP_REGISTER:
			compare_reg_ret(*handle, op->reg, eop->reg, false);
			break;
		case M680X_OP_IMMEDIATE:
			compare_int32_ret(op->imm, eop->imm, false);
			break;
		case M680X_OP_EXTENDED:
			compare_uint16_ret(op->ext.address, eop->ext_address,
					   false);
			compare_tbool_ret(op->ext.indirect, eop->ext_indirect,
					  false);
			break;
		case M680X_OP_DIRECT:
			if (eop->direct_addr_set) {
				compare_uint8_ret(op->direct_addr,
						  eop->direct_addr, false);
			} else {
				assert(eop->direct_addr == 0);
			}
			break;
		case M680X_OP_RELATIVE:
			compare_uint16_ret(op->rel.address, eop->rel_address,
					   false);
			compare_int16_ret(op->rel.offset, eop->rel_offset,
					  false);
			break;
		case M680X_OP_CONSTANT:
			compare_uint8_ret(op->const_val, eop->const_val, false);
			break;
		case M680X_OP_INDEXED:
			if (!eop->idx) {
				break;
			}
			compare_reg_ret(*handle, op->idx.base_reg,
					eop->idx->base_reg, false);
			compare_reg_ret(*handle, op->idx.offset_reg,
					eop->idx->offset_reg, false);
			if (eop->idx->offset) {
				compare_int16_ret(op->idx.offset,
						  eop->idx->offset, false);
			}
			if (eop->idx->offset_addr) {
				compare_uint16_ret(op->idx.offset_addr,
						   eop->idx->offset_addr,
						   false);
			}
			if (eop->idx->offset_bits) {
				compare_uint8_ret(op->idx.offset_bits,
						  eop->idx->offset_bits, false);
			}
			if (eop->idx->inc_dec) {
				compare_int8_ret(op->idx.inc_dec,
						 eop->idx->inc_dec, false);
			}
			compare_bit_flags_ret(op->idx.flags, eop->idx->flags,
					      eop->idx->flags_count, false);
			break;
		}
	}

	return true;
}
