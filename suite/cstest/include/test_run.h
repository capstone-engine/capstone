// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TESTRUN_H
#define TESTRUN_H

#include "test_case.h"
#include <stdint.h>

typedef enum {
	TEST_RUN_SUCCESS = 0, ///< All test cases succeeded.
	TEST_RUN_FAILURE = 1, ///< At least one test case failed.
	TEST_RUN_ERROR = 2, ///< Test run had errors.
} TestRunResult;

typedef struct {
	uint32_t valid_test_files; ///< Total number of test files.
	uint32_t invalid_files; ///< Number of invalid files.
	uint32_t tc_total; ///< Total number of test cases.
	uint32_t successful; ///< Number of successful test cases.
	uint32_t failed; ///< Number of failed test cases.
	uint32_t errors; ///< Number errors (parsing errors etc).
	uint32_t skipped; ///< Number skipped test cases.
	uint32_t decoded_insns; ///< Number of total decoded instructions.
} TestRunStats;

typedef struct {
	uint32_t case_cnt;
	TestCase *cases;
} TestRun;

/* CYAML configuration. */
static const cyaml_config_t cyaml_config = {
	.log_fn = cyaml_log, /* Use the default logging function. */
	.mem_fn = cyaml_mem, /* Use the default memory allocator. */
	.log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

typedef struct {
	size_t arch_bits; ///< Bits of the architecture.
	TestCase *tcase; ///< The test case to check.
	csh handle; ///< The Capstone instance for this test. Setup and teared down by the cmocka handlers.
	uint32_t decoded_insns; ///< Counts the number of decoded instructions of this test case.
} UnitTestState;

TestRunResult cstest_run_tests(char **test_file_paths, uint32_t path_count,
			       TestRunStats *stats);

#endif // TESTRUN_H
