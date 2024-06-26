// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TESTCASE_H
#define TESTCASE_H

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdint.h>

/// Enumeration of all possible fields to check.
/// Enum is incomplete, because it is only used to mark the fields
/// checked during DIET testing.
typedef enum {
	TC_FIELD_ALL, ///< (Default) Test all fields given in the yaml file.
	TC_FIELD_ID,  ///< The cs_insn->id
} TestCaseField;

/// Input data for a test case.
typedef struct {
	uint8_t *bytes; // mandatory
	uint32_t bytes_count; // Filled by cyaml
	char *arch;	      // mandatory
	uint64_t address;
	char **options;	      // mandatory
	uint32_t options_count; // Filled by cyaml
} TestInput;

TestInput *test_input_new();
void test_input_free(TestInput *test_input);
TestInput *test_input_clone(TestInput *test_input);
char *test_input_stringify(const TestInput *test_case);
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
	uint32_t id;
	char *op_str; // mandatory
	bool is_alias;
	uint64_t alias_id;
	char *mnemonic;
	// TODO: details
} TestInsnData;

TestInsnData *test_insn_data_new();
void test_insn_data_free(TestInsnData *test_insn_data);
TestInsnData *test_insn_data_clone(TestInsnData *test_insn_data);

static const cyaml_schema_field_t test_insn_data_mapping_schema[] = {
	CYAML_FIELD_UINT("id", CYAML_FLAG_SCALAR_PLAIN | CYAML_FLAG_OPTIONAL,
			 TestInsnData, id),
	CYAML_FIELD_STRING_PTR("op_str", CYAML_FLAG_POINTER, TestInsnData,
			       op_str, 0, CYAML_UNLIMITED),
	CYAML_FIELD_BOOL("is_alias", CYAML_FLAG_OPTIONAL, TestInsnData,
			 is_alias),
	CYAML_FIELD_UINT("alias_id",
			 CYAML_FLAG_SCALAR_PLAIN | CYAML_FLAG_OPTIONAL,
			 TestInsnData, alias_id),
	CYAML_FIELD_STRING_PTR("mnemonic",
			       CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			       TestInsnData, mnemonic, 0, CYAML_UNLIMITED),
	// TODO details
	CYAML_FIELD_END
};

/// The exected data for a test. This can hold mutiple instructions
/// if enough bytes were given.
typedef struct {
	TestInsnData *insns;  ///< Zero to N disassembled instructions.
	uint32_t insns_count; ///< Filled by cyaml.
} TestExpected;

TestExpected *test_expected_new();
void test_expected_free(TestExpected *test_expected);
TestExpected *test_expected_clone(TestExpected *test_expected);

static const cyaml_schema_value_t insn_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, TestInsnData,
			    test_insn_data_mapping_schema),
};

static const cyaml_schema_field_t test_expected_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE("insns", CYAML_FLAG_POINTER, TestExpected, insns,
			     &insn_schema, 0, CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

/// A single test case.
typedef struct {
	TestInput input;       ///< Input data for a test case
	TestExpected expected; ///< Expected data of the test case.
	char **fields_to_check; ///< If NULL, all fields are checked. Otherwise only the specified.
	uint32_t fields_to_check_count; // Filled by cyaml
} TestCase;

TestCase *test_case_new();
void test_case_free(TestCase *test_case);
TestCase *test_case_clone(TestCase *test_case);

/// A single field name string
static const cyaml_schema_value_t field_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_case_mapping_schema[] = {
	CYAML_FIELD_MAPPING("input", CYAML_FLAG_DEFAULT, TestCase, input,
			    test_input_mapping_schema),
	CYAML_FIELD_MAPPING("expected", CYAML_FLAG_DEFAULT, TestCase, expected,
			    test_expected_mapping_schema),
	CYAML_FIELD_SEQUENCE("fields_to_check",
			     CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, TestCase,
			     fields_to_check, &field_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_case_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, TestCase,
			    test_case_mapping_schema),
};

typedef struct {
	TestCase *test_cases;
	uint32_t test_cases_count;
} TestFile;

TestFile *test_file_new();
void test_file_free(TestFile *test_file);
TestFile *test_file_clone(TestFile *test_file);

static const cyaml_schema_field_t test_file_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE("test_cases", CYAML_FLAG_POINTER, TestFile,
			     test_cases, &test_case_schema, 1,
			     CYAML_UNLIMITED), // 1-MAX options
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_file_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, TestFile,
			    test_file_mapping_schema),
};

/// The result of a test case.
typedef struct {
	bool successful; ///< True if test succeeded, false otherwise.
} TestCaseResult;

#endif			 // TESTCASE_H
