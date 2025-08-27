// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TESTCASE_H
#define TESTCASE_H

#include "test_detail.h"
#include <cyaml/cyaml.h>
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdint.h>

/// Input data for a test case.
typedef struct {
	char *name;
	uint8_t *bytes; // mandatory
	uint32_t bytes_count; // Filled by cyaml
	char *arch; // mandatory
	uint64_t address;
	char **options; // mandatory
	uint32_t options_count; // Filled by cyaml
} TestInput;

TestInput *test_input_new();
void test_input_free(TestInput *test_input);
TestInput *test_input_clone(TestInput *test_input);
char *test_input_stringify(const TestInput *test_input, const char *postfix);
cs_arch test_input_get_cs_arch(const TestInput *test_input);
cs_mode test_input_get_cs_mode(const TestInput *test_input);
void test_input_get_cs_option(const TestInput *test_input, cs_opt_type *otype,
			      cs_opt_value *oval);

/// A single byte
static const cyaml_schema_value_t byte_schema = {
	CYAML_VALUE_UINT(CYAML_FLAG_DEFAULT, uint8_t),
};

/// A single option string
static const cyaml_schema_value_t option_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_input_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestInput, name, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE("bytes", CYAML_FLAG_POINTER, TestInput, bytes,
			     &byte_schema, 0, CYAML_UNLIMITED), // 0-MAX bytes
	CYAML_FIELD_STRING_PTR("arch", CYAML_FLAG_POINTER, TestInput, arch, 0,
			       CYAML_UNLIMITED),
	CYAML_FIELD_UINT("address",
			 CYAML_FLAG_SCALAR_PLAIN | CYAML_FLAG_OPTIONAL,
			 TestInput, address),
	CYAML_FIELD_SEQUENCE("options", CYAML_FLAG_POINTER, TestInput, options,
			     &option_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

/// Data compared to the produced cs_insn.
typedef struct {
	char *id;
	char *asm_text; // mandatory
	char *op_str;
	tbool is_alias;
	tbool illegal;
	uint32_t size;
	char *alias_id;
	char *mnemonic;
	TestDetail *details;
} TestInsnData;

TestInsnData *test_insn_data_new();
void test_insn_data_free(TestInsnData *test_insn_data);
TestInsnData *test_insn_data_clone(TestInsnData *test_insn_data);

static const cyaml_schema_field_t test_insn_data_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestInsnData, id, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR("asm_text", CYAML_FLAG_POINTER, TestInsnData,
			       asm_text, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"op_str", CYAML_FLAG_POINTER_NULL_STR | CYAML_FLAG_OPTIONAL,
		TestInsnData, op_str, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT("is_alias", CYAML_FLAG_OPTIONAL, TestInsnData,
			is_alias),
	CYAML_FIELD_INT("illegal", CYAML_FLAG_OPTIONAL, TestInsnData, illegal),
	CYAML_FIELD_UINT("size", CYAML_FLAG_OPTIONAL, TestInsnData, size),
	CYAML_FIELD_STRING_PTR("alias_id",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestInsnData, alias_id, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"mnemonic", CYAML_FLAG_POINTER_NULL_STR | CYAML_FLAG_OPTIONAL,
		TestInsnData, mnemonic, 0, CYAML_UNLIMITED),
	CYAML_FIELD_MAPPING_PTR(
		"details", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
		TestInsnData, details, test_detail_mapping_schema),
	CYAML_FIELD_END
};

/// The expected data for a test. This can hold multiple instructions
/// if enough bytes were given.
typedef struct {
	TestInsnData **insns; ///< Zero to N disassembled instructions.
	uint32_t insns_count; ///< Filled by cyaml.
} TestExpected;

TestExpected *test_expected_new();
void test_expected_free(TestExpected *test_expected);
TestExpected *test_expected_clone(TestExpected *test_expected);
void test_expected_compare(csh *handle, TestExpected *expected, cs_insn *insns,
			   size_t insns_count, size_t arch_bits);

static const cyaml_schema_value_t insn_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestInsnData,
			    test_insn_data_mapping_schema),
};

static const cyaml_schema_field_t test_expected_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE("insns", CYAML_FLAG_POINTER, TestExpected, insns,
			     &insn_schema, 0, CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

/// A single test case.
typedef struct {
	TestInput *input; ///< Input data for a test case
	TestExpected *expected; ///< Expected data of the test case.
	bool skip; ///< If set, the test is skipped
	char *skip_reason; ///< Reason this test is skipped.
} TestCase;

TestCase *test_case_new();
void test_case_free(TestCase *test_case);
TestCase *test_case_clone(TestCase *test_case);

static const cyaml_schema_field_t test_case_mapping_schema[] = {
	CYAML_FIELD_MAPPING_PTR("input", CYAML_FLAG_POINTER, TestCase, input,
				test_input_mapping_schema),
	CYAML_FIELD_MAPPING_PTR("expected", CYAML_FLAG_POINTER, TestCase,
				expected, test_expected_mapping_schema),
	CYAML_FIELD_BOOL("skip", CYAML_FLAG_OPTIONAL, TestCase, skip),
	CYAML_FIELD_STRING_PTR("skip_reason",
			       CYAML_FLAG_POINTER_NULL_STR |
				       CYAML_FLAG_OPTIONAL,
			       TestCase, skip_reason, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_case_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestCase,
			    test_case_mapping_schema),
};

typedef struct {
	char *filename; ///< Filename. NOT filled by cyaml.
	TestCase **test_cases;
	uint32_t test_cases_count;
} TestFile;

TestFile *test_file_new();
void test_file_free(TestFile *test_file);
TestFile *test_file_clone(TestFile *test_file);

static const cyaml_schema_field_t test_file_mapping_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"filename", CYAML_FLAG_OPTIONAL | CYAML_FLAG_POINTER_NULL_STR,
		TestFile, filename, 0, 0),
	CYAML_FIELD_SEQUENCE("test_cases", CYAML_FLAG_POINTER, TestFile,
			     test_cases, &test_case_schema, 1,
			     CYAML_UNLIMITED), // 1-MAX options
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_file_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestFile,
			    test_file_mapping_schema),
};

#endif // TESTCASE_H
