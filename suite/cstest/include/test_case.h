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

/// Data compared to the produced cs_insn.
typedef struct {
	unsigned int id;  // mandatory
	uint64_t address; // mandatory
	char *op_str;	  // mandatory
	bool is_alias;
	uint64_t alias_id;
	char *mnemonic;
	// TODO: details
} TestInsnData;

/// The exected data for a test. This can hold mutiple instructions
/// if enough bytes were given.
typedef struct {
	TestInsnData *insns;  ///< Zero to N disassembled instructions.
	uint32_t insns_count; ///< Filled by cyaml.
} TestExpected;

/// A single test case.
typedef struct {
	TestInput input;       ///< Input data for a test case
	TestExpected expected; ///< Expected data of the test case.
	const char *
		fields_to_check; ///< If NULL, all fields are checkd. Otherwise only the specified.
} TestCase;

/// The result of a test case.
typedef struct {
	bool successful; ///< True if test succeeded, false otherwise.
} TestCaseResult;

#endif			 // TESTCASE_H
