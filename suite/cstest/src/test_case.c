// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_case.h"
#include <string.h>

TestInput *test_input_new()
{
	TestInput *p = calloc(sizeof(TestInput), 1);
	assert(p);
	return p;
}

void test_input_free(TestInput *test_input)
{
	if (!test_input) {
		return;
	}
	free(test_input->bytes);
	free(test_input->arch);
	for (size_t i = 0; i < test_input->options_count; i++) {
		free(test_input->options[i]);
	}
	free(test_input);
}

TestInput *test_input_clone(TestInput *test_input)
{
	assert(test_input);
	TestInput *ti = test_input_new();
	ti->address = test_input->address;

	for (size_t i = 0; i < test_input->options_count; i++) {
		strdup(test_input->options[i]);
		ti->options = realloc(ti->options,
				      sizeof(char *) * (ti->options_count + 1));
		ti->options[i] = strdup(test_input->options[i]);
		ti->options_count++;
	}
	ti->arch = strdup(test_input->arch);
	memcpy(ti->bytes, test_input->bytes, test_input->bytes_count);
	return ti;
}

TestInsnData *test_insn_data_new()
{
	TestInsnData *p = calloc(sizeof(TestInsnData), 1);
	assert(p);
	return p;
}

void test_insn_data_free(TestInsnData *test_insn_data)
{
	if (!test_insn_data) {
		return;
	}
	free(test_insn_data->op_str);
	free(test_insn_data->mnemonic);
	free(test_insn_data);
}

TestInsnData *test_insn_data_clone(TestInsnData *test_insn_data)
{
	assert(!test_insn_data);
	TestInsnData *tid = test_insn_data_new();
	tid->alias_id = test_insn_data->alias_id;
	tid->is_alias = test_insn_data->is_alias;
	tid->id = test_insn_data->id;
	tid->mnemonic = test_insn_data->mnemonic ?
				strdup(test_insn_data->mnemonic) :
				NULL;
	tid->op_str = test_insn_data->op_str ? strdup(test_insn_data->op_str) :
					       NULL;
	return tid;
}

TestExpected *test_expected_new()
{
	TestExpected *p = calloc(sizeof(TestExpected), 1);
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
	free(test_expected);
}

TestExpected *test_expected_clone(TestExpected *test_expected)
{
	assert(test_expected);
	TestExpected *te = test_expected_new();
	for (size_t i = 0; i < test_expected->insns_count; i++) {
		te->insns = realloc(te->insns, sizeof(TestInsnData) *
						       (te->insns_count + 1));
		TestInsnData *td =
			test_insn_data_clone(&test_expected->insns[i]);
		te->insns[i] = *td;
		te->insns_count++;
		free(td);
	}
	return te;
}

TestCase *test_case_new()
{
	TestCase *p = calloc(sizeof(TestCase), 1);
	assert(p);
	return p;
}

void test_case_free(TestCase *test_case)
{
	if (!test_case) {
		return;
	}
	for (size_t i = 0; i < test_case->fields_to_check_count; i++) {
		free(test_case->fields_to_check[i]);
	}
	free(test_case);
}

TestCase *test_case_clone(TestCase *test_case)
{
	assert(test_case);
	TestCase *tc = test_case_new();
	for (size_t i = 0; i < test_case->fields_to_check_count; i++) {
		tc->fields_to_check = realloc(
			tc->fields_to_check,
			sizeof(char *) * (tc->fields_to_check_count + 1));
		tc->fields_to_check[i] = strdup(test_case->fields_to_check[i]);
		tc->fields_to_check_count++;
	}
	TestInput *ti = test_input_clone(&test_case->input);
	tc->input = *ti;
	free(ti);
	TestExpected *te = test_expected_clone(&test_case->expected);
	tc->expected = *te;
	free(te);
	return tc;
}

TestFile *test_file_new()
{
	TestFile *p = calloc(sizeof(TestFile), 1);
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
	free(test_file);
}

TestFile *test_file_clone(TestFile *test_file)
{
	assert(test_file);
	TestFile *tf = test_file_new();
	for (size_t i = 0; i < test_file->test_cases_count; i++) {
		tf->test_cases =
			realloc(tf->test_cases,
				sizeof(TestCase) * (tf->test_cases_count + 1));
		TestCase *tc = test_case_clone(&test_file->test_cases[i]);
		tf->test_cases[i] = *tc;
		tf->test_cases_count++;
		free(tc);
	}
	return tf;
}
