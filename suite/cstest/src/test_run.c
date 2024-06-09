// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include <stdbool.h>

/// Runs runs all valid tests in the given @test_files
/// and returns the result.
TestRunResult run_tests(char **test_files, TestRunStats *stats)
{
	return stats->total == stats->successful && stats->failed == 0 ?
		       TRSuccess :
		       TRFailure;
}
