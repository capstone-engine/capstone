// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TESTRUN_H
#define TESTRUN_H

#include "test_case.h"
#include <stdint.h>

typedef enum {
	TRSuccess = 0, ///< All tests succeeded.
	TRFailure = 1, ///< At least one test failed.
	TRError = 2,   ///< Aborted test run due to error.
} TestRunResult;

typedef struct {
	uint32_t total;	     ///< Total number of tests.
	uint32_t successful; ///< Number of successful tests.
	uint32_t failed;     ///< Number of failed tests.
} TestRunStats;

typedef struct {
	uint32_t case_cnt;
	TestCase *cases;
} TestRun;

TestRunResult run_tests(char **test_files, TestRunStats *stats);

#endif // TESTRUN_H
