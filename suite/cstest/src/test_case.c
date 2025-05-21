// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"
#include "test_detail.h"
#include "test_case.h"
#include "test_compare.h"
#include "helper.h"
#include "../../../utils.h"
#include <stdio.h>
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
	cs_mem_free(test_input->name);
	cs_mem_free(test_input->bytes);
	cs_mem_free(test_input->arch);
	for (size_t i = 0; i < test_input->options_count; i++) {
		cs_mem_free(test_input->options[i]);
	}
	cs_mem_free(test_input->options);
	cs_mem_free(test_input);
}

TestInput *test_input_clone(TestInput *test_input)
{
	assert(test_input);
	TestInput *ti = test_input_new();
	ti->address = test_input->address;

	for (size_t i = 0; i < test_input->options_count; i++) {
		ti->options = cs_mem_realloc(
			ti->options, sizeof(char *) * (ti->options_count + 1));
		ti->options[i] = cs_strdup(test_input->options[i]);
		ti->options_count++;
	}
	ti->name = test_input->name ? cs_strdup(test_input->name) : NULL;
	ti->arch = cs_strdup(test_input->arch);
	ti->bytes = cs_mem_calloc(sizeof(uint8_t), test_input->bytes_count);
	ti->bytes_count = test_input->bytes_count;
	memcpy(ti->bytes, test_input->bytes, test_input->bytes_count);
	return ti;
}

char *test_input_stringify(const TestInput *test_input, const char *postfix)
{
	size_t msg_len = 2048;
	char *msg = cs_mem_calloc(sizeof(char), msg_len);
	char *byte_seq =
		byte_seq_to_str(test_input->bytes, test_input->bytes_count);
	if (!msg) {
		cs_mem_free(byte_seq);
		return NULL;
	}
	char opt_seq[128] = { 0 };
	str_append_no_realloc(opt_seq, sizeof(opt_seq), "[");
	for (size_t i = 0; i < test_input->options_count; ++i) {
		str_append_no_realloc(opt_seq, sizeof(opt_seq), test_input->options[i]);
		if (i < test_input->options_count - 1) {
			str_append_no_realloc(opt_seq, sizeof(opt_seq), ", ");
		}
	}
	str_append_no_realloc(opt_seq, sizeof(opt_seq), "]");
	cs_snprintf(msg, msg_len,
		    "%sTestInput { arch: %s, options: %s, addr: 0x%" PRIx64
		    ", bytes: %s }",
		    postfix, test_input->arch, opt_seq, test_input->address,
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
	cs_mem_free(test_insn_data->asm_text);
	cs_mem_free(test_insn_data->op_str);
	cs_mem_free(test_insn_data->mnemonic);
	cs_mem_free(test_insn_data->id);
	cs_mem_free(test_insn_data->alias_id);
	test_detail_free(test_insn_data->details);
	cs_mem_free(test_insn_data);
}

TestInsnData *test_insn_data_clone(TestInsnData *test_insn_data)
{
	assert(test_insn_data);
	TestInsnData *tid = test_insn_data_new();
	tid->alias_id = test_insn_data->alias_id ?
				cs_strdup(test_insn_data->alias_id) :
				NULL;
	tid->id = test_insn_data->id ?
				cs_strdup(test_insn_data->id) :
				NULL;
	tid->is_alias = test_insn_data->is_alias;
	tid->illegal = test_insn_data->illegal;
	tid->mnemonic = test_insn_data->mnemonic ?
				cs_strdup(test_insn_data->mnemonic) :
				NULL;
	tid->op_str = test_insn_data->op_str ?
			      cs_strdup(test_insn_data->op_str) :
			      NULL;
	tid->asm_text = test_insn_data->asm_text ?
				cs_strdup(test_insn_data->asm_text) :
				NULL;
	if (test_insn_data->details) {
		tid->details = test_detail_clone(test_insn_data->details);
	}
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
		test_insn_data_free(test_expected->insns[i]);
	}
	cs_mem_free(test_expected->insns);
	cs_mem_free(test_expected);
}

TestExpected *test_expected_clone(TestExpected *test_expected)
{
	assert(test_expected);
	TestExpected *te = test_expected_new();
	te->insns = cs_mem_calloc(sizeof(TestInsnData *),
				  test_expected->insns_count);
	for (size_t i = 0; i < test_expected->insns_count; i++) {
		te->insns[i] = test_insn_data_clone(test_expected->insns[i]);
		te->insns_count++;
	}
	return te;
}

/// Compares the given @asm_text to the @expected one.
/// Because Capstone sometimes deviates from the LLVM syntax
/// the strings don't need to be the same to be considered a valid match.
/// E.g. Capstone sometimes prints decimal numbers instead of hexadecimal
/// for readability.
static bool compare_asm_text(const char *asm_text, const char *expected,
			     size_t arch_bits)
{
	if (!asm_text || !expected) {
		fprintf(stderr, "[!] asm_text or expected was NULL\n");
		return false;
	}
	if (strcmp(asm_text, expected) == 0) {
		return true;
	}
	// Normalize both strings
	char asm_copy[MAX_ASM_TXT_MEM] = { 0 };
	strncpy(asm_copy, asm_text, MAX_ASM_TXT_MEM - 1);
	trim_str(asm_copy);
	replace_hex(asm_copy, sizeof(asm_copy));
	replace_negative(asm_copy, sizeof(asm_copy), arch_bits);
	norm_spaces(asm_copy);
	str_to_lower(asm_copy);

	char expected_copy[MAX_ASM_TXT_MEM] = { 0 };
	strncpy(expected_copy, expected, MAX_ASM_TXT_MEM - 1);
	trim_str(expected_copy);
	replace_hex(expected_copy, sizeof(expected_copy));
	replace_negative(expected_copy, sizeof(expected_copy), arch_bits);
	norm_spaces(expected_copy);
	str_to_lower(expected_copy);

	if (strcmp(asm_copy, expected_copy) == 0) {
		return true;
	}

	fprintf(stderr,
		"Normalized asm-text doesn't match:\n"
		"decoded:  '%s'\n"
		"expected: '%s'\n",
		asm_copy, expected_copy);
	return false;
}

static bool ids_match(uint32_t actual, const char *expected) {
       compare_enum_ret(actual, expected, false);
       return true;
}

/// Compares the decoded instructions @insns against the @expected values and returns the result.
void test_expected_compare(csh *handle, TestExpected *expected, cs_insn *insns,
			   size_t insns_count, size_t arch_bits)
{
	assert_int_equal(insns_count, expected->insns_count);
	for (size_t i = 0; i < insns_count; ++i) {
		TestInsnData *expec_data = expected->insns[i];
		// Test mandatory fields first
		// The asm text is saved differently for different architectures.
		// Either all in op_str or split in mnemonic and op_str
		char asm_text[256] = { 0 };
		if (insns[i].mnemonic[0] != '\0') {
			str_append_no_realloc(asm_text, sizeof(asm_text),
				      insns[i].mnemonic);
			str_append_no_realloc(asm_text, sizeof(asm_text), " ");
		}
		if (insns[i].op_str[0] != '\0') {
			str_append_no_realloc(asm_text, sizeof(asm_text),
				      insns[i].op_str);
		}
		if (!compare_asm_text(asm_text, expec_data->asm_text,
				      arch_bits)) {
			fail_msg("asm-text mismatch\n");
		}

		// Not mandatory fields. If not initialized they should still match.
		if (expec_data->id) {
			assert_true(ids_match((uint32_t)insns[i].id,
								expec_data->id));
		}
		if (expec_data->is_alias != 0) {
			if (expec_data->is_alias > 0) {
				assert_true(insns[i].is_alias);
			} else {
				assert_false(insns[i].is_alias);
			}
		}
		if (expec_data->illegal != 0) {
			if (expec_data->illegal > 0) {
				assert_true(insns[i].illegal);
			} else {
				assert_false(insns[i].illegal);
			}
		}
		if (expec_data->alias_id) {
			assert_true(ids_match((uint32_t)insns[i].alias_id,
								expec_data->alias_id));
		}
		if (expec_data->mnemonic) {
			assert_string_equal(insns[i].mnemonic,
					    expec_data->mnemonic);
		}
		if (expec_data->op_str) {
			assert_string_equal(insns[i].op_str,
					    expec_data->op_str);
		}
		if (expec_data->details) {
			if (!insns[i].detail) {
				fprintf(stderr, "detail is NULL\n");
				assert_non_null(insns[i].detail);
			}
			assert_true(test_expected_detail(handle, &insns[i],
							 expec_data->details));
		}
	}
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
	test_input_free(test_case->input);
	test_expected_free(test_case->expected);
	cs_mem_free(test_case->skip_reason);
	cs_mem_free(test_case);
}

TestCase *test_case_clone(TestCase *test_case)
{
	assert(test_case);
	TestCase *tc = test_case_new();
	TestInput *ti = test_input_clone(test_case->input);
	tc->input = ti;
	TestExpected *te = test_expected_clone(test_case->expected);
	tc->expected = te;
	tc->skip = test_case->skip;
	if (tc->skip) {
		tc->skip_reason = strdup(test_case->skip_reason);
	}
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

	for (size_t i = 0; i < test_file->test_cases_count; ++i) {
		test_case_free(test_file->test_cases[i]);
	}

	cs_mem_free(test_file->test_cases);
	cs_mem_free(test_file->filename);
	test_file->filename = NULL;
	cs_mem_free(test_file);
}

TestFile *test_file_clone(TestFile *test_file)
{
	assert(test_file);
	TestFile *tf = test_file_new();
	tf->filename = test_file->filename ? strdup(test_file->filename) : NULL;
	tf->test_cases =
		cs_mem_calloc(sizeof(TestCase *), test_file->test_cases_count);

	for (size_t i = 0; i < test_file->test_cases_count;
	     i++, tf->test_cases_count++) {
		TestCase *tc = test_case_clone(test_file->test_cases[i]);
		tf->test_cases[i] = tc;
	}
	return tf;
}
