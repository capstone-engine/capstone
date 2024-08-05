// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_DETAIL_EVM_H
#define TEST_DETAIL_EVM_H

#include <cyaml/cyaml.h>
#include <capstone/capstone.h>

typedef struct {
	unsigned char pop;
	unsigned char push;
	unsigned int fee;
} TestDetailEVM;

static const cyaml_schema_field_t test_detail_evm_mapping_schema[] = {
	CYAML_FIELD_UINT("pop", CYAML_FLAG_OPTIONAL, TestDetailEVM, pop),
	CYAML_FIELD_UINT("push", CYAML_FLAG_OPTIONAL, TestDetailEVM, push),
	CYAML_FIELD_UINT("fee", CYAML_FLAG_OPTIONAL, TestDetailEVM, fee),
	CYAML_FIELD_END
};

TestDetailEVM *test_detail_evm_new();
TestDetailEVM *test_detail_evm_clone(const TestDetailEVM *detail);
void test_detail_evm_free(TestDetailEVM *detail);

bool test_expected_evm(csh *handle, const cs_evm *actual,
		       const TestDetailEVM *expected);

#endif // TEST_DETAIL_EVM_H
