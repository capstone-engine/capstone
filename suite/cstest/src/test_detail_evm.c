// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_evm.h"
#include <capstone/capstone.h>

TestDetailEVM *test_detail_evm_new()
{
	return cs_mem_calloc(sizeof(TestDetailEVM), 1);
}

void test_detail_evm_free(TestDetailEVM *detail)
{
	if (!detail) {
		return;
	}
	cs_mem_free(detail);
}

TestDetailEVM *test_detail_evm_clone(const TestDetailEVM *detail)
{
	TestDetailEVM *clone = test_detail_evm_new();
	clone->fee = detail->fee;
	clone->pop = detail->pop;
	clone->push = detail->push;
	return clone;
}

bool test_expected_evm(csh *handle, const cs_evm *actual,
		       const TestDetailEVM *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->fee, expected->fee, false);
	compare_uint8_ret(actual->pop, expected->pop, false);
	compare_uint8_ret(actual->push, expected->push, false);

	return true;
}
