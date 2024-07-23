// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_aarch64.h"
#include "test_mapping.h"
#include "../../../cs_priv.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailAArch64 *test_aarch64_detail_new()
{
	return cs_mem_calloc(sizeof(TestDetailAArch64), 1);
}

void test_aarch64_detail_free(TestDetailAArch64 *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_aarch64_detail_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->cc);
	cs_mem_free(detail);
}

TestDetailAArch64 *test_aarch64_detail_clone(TestDetailAArch64 *detail)
{
	TestDetailAArch64 *clone = test_aarch64_detail_new();
	clone->cc = detail->cc ? strdup(detail->cc) : NULL;
	clone->update_flags = detail->update_flags;
	clone->post_index = detail->post_index;

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailAArch64Op),
							detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_aarch64_detail_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailAArch64Op *test_aarch64_detail_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailAArch64Op), 1);
}

TestDetailAArch64Op *test_aarch64_detail_op_clone(TestDetailAArch64Op *op)
{
	TestDetailAArch64Op *clone = test_aarch64_detail_op_new();

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
	clone->mem_disp = op->mem_disp;
	clone->imm_range_first = op->imm_range_first;
	clone->imm_range_offset = op->imm_range_offset;
	clone->fp = op->fp;
	clone->sys_raw_val = op->sys_raw_val;
	clone->shift_value = op->shift_value;
	clone->is_vreg = op->is_vreg;
	clone->vector_index = op->vector_index;
	clone->is_list_member = op->is_list_member;

	return clone;
}

void test_aarch64_detail_op_free(TestDetailAArch64Op *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op->sub_type);
	cs_mem_free(op->access);
	cs_mem_free(op->reg);
	cs_mem_free(op->mem_base);
	cs_mem_free(op->mem_index);
	cs_mem_free(op->shift_type);
	cs_mem_free(op->ext);
	cs_mem_free(op->vas);
	cs_mem_free(op);
}

bool test_expected_aarch64(cs_aarch64 *actual, TestDetailAArch64 *expected)
{
	assert(actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	compare_tbool_ret(actual->update_flags, expected->update_flags, false);
	compare_tbool_ret(actual->post_index, expected->post_index, false);
	return true;
}
