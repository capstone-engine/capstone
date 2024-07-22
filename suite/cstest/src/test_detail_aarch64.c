// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_detail_aarch64.h"
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
	cs_mem_free(detail);
}

TestDetailAArch64 *test_aarch64_detail_clone(TestDetailAArch64 *detail)
{
	TestDetailAArch64 *clone = test_aarch64_detail_new();
	memcpy(clone, detail, sizeof(TestDetailAArch64Op));

	clone->operands = detail->operands_count > 0 ?
				  cs_mem_calloc(sizeof(TestDetailAArch64Op),
						detail->operands_count) :
				  NULL;
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

TestDetailAArch64Op *test_aarch64_detail_op_clone(TestDetailAArch64Op *detail)
{
	TestDetailAArch64Op *clone = test_aarch64_detail_op_new();
	memcpy(clone, detail, sizeof(TestDetailAArch64Op));
	return clone;
}

void test_aarch64_detail_op_free(TestDetailAArch64Op *detail)
{
	if (!detail) {
		return;
	}
	cs_mem_free(detail);
}

bool test_expected_aarch64(cs_detail *cs_detail, TestDetailAArch64 *expected)
{
	assert(cs_detail && expected);
	if (cs_detail->aarch64.op_count != expected->operands_count) {
		fprintf(stderr, "op_count: %" PRId32 " != %" PRId32 "\n",
			cs_detail->aarch64.op_count, expected->operands_count);
		return false;
	}
	return true;
}
