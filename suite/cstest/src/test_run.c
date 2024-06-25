// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include "cyaml/cyaml.h"
#include <stdbool.h>
#include <stdio.h>

static TestRunResult get_test_run_result(const TestRunStats *stats)
{
	if (stats->total != stats->successful + stats->failed) {
		fprintf(stderr,
			"Inconsistent statistics: total != successful + failed");
		return TRError;
	}

	if (stats->errors != 0) {
		return TRError;
	} else if (stats->failed != 0) {
		return TRFailure;
	}
	return TRSuccess;
}

/// Runs runs all valid tests in the given @test_files
/// and returns the result as well as statistics in @stats.
TestRunResult run_tests(char **test_files, uint32_t file_count,
			TestRunStats *stats)
{
	for (size_t i = 0; i < file_count; ++i) {
		TestFile *test_file = NULL;
		cyaml_err_t err = cyaml_load_file(test_files[i], &cyaml_config,
						  &test_file_schema,
						  (cyaml_data_t **)&test_file,
						  NULL);
		if (err != CYAML_OK || !test_file) {
			fprintf(stderr, "Failed to parse test file '%s'\n",
				test_files[i]);
			fprintf(stderr, "Error: '%s'\n", !test_file ? "Empty file" : cyaml_strerror(err));
			stats->errors++;
			continue;
		}
	}
	return get_test_run_result(stats);
}
