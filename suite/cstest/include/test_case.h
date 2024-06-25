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
	TC_FIELD_ALL,	  ///< (Default) Test all fields given in the yaml file.
	TC_FIELD_ID,	  ///< The cs_insn->id
	TC_FIELD_ADDRESS, ///< The cs_insn->address
} TestCaseField;

/// Input data for a test case.
typedef struct {
	uint8_t *bytes;		// mandatory
	uint32_t bytes_count;	// Filled by cyaml
	const char *arch;	// mandatory
	uint64_t address;	// mandatory
	const char **options;	// mandatory
	uint32_t options_count; // Filled by cyaml
} TestInput;

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
	CYAML_FIELD_STRING("arch", CYAML_FLAG_POINTER, TestInput, arch, 0),
	CYAML_FIELD_UINT("address", CYAML_FLAG_SCALAR_PLAIN, TestInput,
			 address),
	CYAML_FIELD_SEQUENCE("options", CYAML_FLAG_POINTER, TestInput, options,
			     &option_schema, 0,
			     CYAML_UNLIMITED), // 0-MAX options
	CYAML_FIELD_END
};

/// Data compared to the produced cs_insn.
typedef struct {
	uint32_t id;	  // mandatory
	uint64_t address; // mandatory
	char *op_str;	  // mandatory
	bool is_alias;
	uint64_t alias_id;
	char *mnemonic;
	// TODO: details
} TestInsnData;

static const cyaml_schema_field_t test_insn_data_mapping_schema[] = {
	CYAML_FIELD_UINT("id", CYAML_FLAG_SCALAR_PLAIN, TestInsnData, id),
	CYAML_FIELD_UINT("address", CYAML_FLAG_SCALAR_PLAIN, TestInsnData,
			 address),
	CYAML_FIELD_STRING("op_str", CYAML_FLAG_POINTER, TestInsnData, op_str,
			   0),
	CYAML_FIELD_BOOL("is_alias", CYAML_FLAG_OPTIONAL, TestInsnData,
			 is_alias),
	CYAML_FIELD_UINT("alias_id",
			 CYAML_FLAG_SCALAR_PLAIN | CYAML_FLAG_OPTIONAL,
			 TestInsnData, alias_id),
	CYAML_FIELD_STRING("mnemonic", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
			   TestInsnData, mnemonic, 0),
	// TODO details
	CYAML_FIELD_END
};

/// The exected data for a test. This can hold mutiple instructions
/// if enough bytes were given.
typedef struct {
	TestInsnData *insns;  ///< Zero to N disassembled instructions.
	uint32_t insns_count; ///< Filled by cyaml.
} TestExpected;

/// A single insn in the instruction data list to check
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
	const char **
		fields_to_check; ///< If NULL, all fields are checked. Otherwise only the specified.
	uint32_t fields_to_check_count; // Filled by cyaml
} TestCase;

/// A single field name string
static const cyaml_schema_value_t field_schema = {
	CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED),
};

static const cyaml_schema_field_t test_case_mapping_schema[] = {
	CYAML_FIELD_MAPPING("input", CYAML_FLAG_DEFAULT, TestCase, input,
			    test_input_mapping_schema),
	CYAML_FIELD_MAPPING("expected", CYAML_FLAG_DEFAULT, TestCase, expected,
			    test_expected_mapping_schema),
	CYAML_FIELD_SEQUENCE("fields_to_check", CYAML_FLAG_POINTER, TestCase,
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

static const cyaml_schema_field_t test_file_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE("test_cases", CYAML_FLAG_POINTER, TestFile,
			     test_cases, &test_case_schema, 1,
			     CYAML_UNLIMITED), // 1-MAX options
	CYAML_FIELD_END
};

static const cyaml_schema_value_t test_file_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, TestFile,
			    test_file_mapping_schema),
};

/// The result of a test case.
typedef struct {
	bool successful; ///< True if test succeeded, false otherwise.
} TestCaseResult;

#endif			 // TESTCASE_H
