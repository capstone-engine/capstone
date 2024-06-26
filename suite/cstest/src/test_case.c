// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_case.h"
#include "../../../utils.h"
#include <string.h>

TestInput *test_input_new()
{
	TestInput *p = cs_mem_calloc(sizeof(TestInput), 1);
	assert(p);
	return p;
}

void test_input_free(TestInput *test_input)
{
	if (!test_input) {
		return;
	}
	cs_mem_free(test_input->bytes);
	cs_mem_free(test_input->arch);
	for (size_t i = 0; i < test_input->options_count; i++) {
		cs_mem_free(test_input->options[i]);
	}
	cs_mem_free(test_input);
}

TestInput *test_input_clone(TestInput *test_input)
{
	assert(test_input);
	TestInput *ti = test_input_new();
	ti->address = test_input->address;

	for (size_t i = 0; i < test_input->options_count; i++) {
		cs_strdup(test_input->options[i]);
		ti->options = cs_mem_realloc(ti->options,
				      sizeof(char *) * (ti->options_count + 1));
		ti->options[i] = cs_strdup(test_input->options[i]);
		ti->options_count++;
	}
	ti->arch = cs_strdup(test_input->arch);
	ti->bytes = cs_mem_calloc(sizeof(uint8_t), test_input->bytes_count);
	memcpy(ti->bytes, test_input->bytes, test_input->bytes_count);
	return ti;
}

char *test_input_stringify(const TestInput *test_input)
{
	size_t msg_len = 256;
	char *msg = cs_mem_calloc(sizeof(char), msg_len);
	char *byte_seq =
		byte_seq_to_str(test_input->bytes, test_input->bytes_count);
	cs_snprintf(msg, msg_len,
		    "TestInput { arch: %s, options: %s, addr: 0x%" PRIx64
		    ", bytes: %s }",
		    test_input->arch, test_input->options, test_input->address,
		    byte_seq);
	cs_mem_free(byte_seq);
	return msg;
}

TestInsnData *test_insn_data_new()
{
	TestInsnData *p = cs_mem_calloc(sizeof(TestInsnData), 1);
	assert(p);
	return p;
}

void test_insn_data_free(TestInsnData *test_insn_data)
{
	if (!test_insn_data) {
		return;
	}
	cs_mem_free(test_insn_data->op_str);
	cs_mem_free(test_insn_data->mnemonic);
	cs_mem_free(test_insn_data);
}

TestInsnData *test_insn_data_clone(TestInsnData *test_insn_data)
{
	assert(test_insn_data);
	TestInsnData *tid = test_insn_data_new();
	tid->alias_id = test_insn_data->alias_id;
	tid->is_alias = test_insn_data->is_alias;
	tid->id = test_insn_data->id;
	tid->mnemonic = test_insn_data->mnemonic ?
				cs_strdup(test_insn_data->mnemonic) :
				NULL;
	tid->op_str = test_insn_data->op_str ? cs_strdup(test_insn_data->op_str) :
					       NULL;
	return tid;
}

TestExpected *test_expected_new()
{
	TestExpected *p = cs_mem_calloc(sizeof(TestExpected), 1);
	assert(p);
	return p;
}

void test_expected_free(TestExpected *test_expected)
{
	if (!test_expected) {
		return;
	}
	for (size_t i = 0; i < test_expected->insns_count; i++) {
		test_insn_data_free(&test_expected->insns[i]);
	}
	cs_mem_free(test_expected);
}

TestExpected *test_expected_clone(TestExpected *test_expected)
{
	assert(test_expected);
	TestExpected *te = test_expected_new();
	for (size_t i = 0; i < test_expected->insns_count; i++) {
		te->insns = cs_mem_realloc(te->insns, sizeof(TestInsnData) *
						       (te->insns_count + 1));
		TestInsnData *td =
			test_insn_data_clone(&test_expected->insns[i]);
		te->insns[i] = *td;
		te->insns_count++;
		cs_mem_free(td);
	}
	return te;
}

/// Compares the decoded instructions @insns against the @expected values and returns the result.
TestCaseResult test_expected_compare(TestExpected *expected, cs_insn *insns, size_t insns_count) {
	return TEST_CASE_FAIL;
}

TestCase *test_case_new()
{
	TestCase *p = cs_mem_calloc(sizeof(TestCase), 1);
	assert(p);
	return p;
}

void test_case_free(TestCase *test_case)
{
	if (!test_case) {
		return;
	}
	cs_mem_free(test_case);
}

TestCase *test_case_clone(TestCase *test_case)
{
	assert(test_case);
	TestCase *tc = test_case_new();
	TestInput *ti = test_input_clone(&test_case->input);
	tc->input = *ti;
	cs_mem_free(ti);
	TestExpected *te = test_expected_clone(&test_case->expected);
	tc->expected = *te;
	cs_mem_free(te);
	return tc;
}

TestFile *test_file_new()
{
	TestFile *p = cs_mem_calloc(sizeof(TestFile), 1);
	assert(p);
	return p;
}

void test_file_free(TestFile *test_file)
{
	if (!test_file) {
		return;
	}
	for (size_t i = 0; i < test_file->test_cases_count; i++) {
		test_case_free(&test_file->test_cases[i]);
	}
	cs_mem_free(test_file);
}

TestFile *test_file_clone(TestFile *test_file)
{
	assert(test_file);
	TestFile *tf = test_file_new();
	for (size_t i = 0; i < test_file->test_cases_count; i++) {
		tf->test_cases =
			cs_mem_realloc(tf->test_cases,
				sizeof(TestCase) * (tf->test_cases_count + 1));
		TestCase *tc = test_case_clone(&test_file->test_cases[i]);
		tf->test_cases[i] = *tc;
		tf->test_cases_count++;
		cs_mem_free(tc);
	}
	return tf;
}
