// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include "cyaml/cyaml.h"
#include "test_case.h"
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

/// Extract all test cases from the given test files.
static TestCase **parse_test_cases(char **test_files, uint32_t file_count,
				   TestRunStats *stats)
{
	TestCase **cases = NULL;
	stats->total = 0;

	for (size_t i = 0; i < file_count; ++i) {
		TestFile *test_file = NULL;
		cyaml_err_t err = cyaml_load_file(test_files[i], &cyaml_config,
						  &test_file_schema,
						  (cyaml_data_t **)&test_file,
						  NULL);
		if (err != CYAML_OK || !test_file) {
			fprintf(stderr, "Failed to parse test file '%s'\n",
				test_files[i]);
			fprintf(stderr, "Error: '%s'\n",
				!test_file && err == CYAML_OK ?
					"Empty file" :
					cyaml_strerror(err));
			stats->errors++;
			continue;
		}

		// Copy all test cases of a test file
		cases = realloc(cases, sizeof(TestCase *) * stats->total +
					       test_file->test_cases_count);
		for (size_t i = 0; i < test_file->test_cases_count; ++i) {
			cases[stats->total] =
				test_case_clone(&test_file->test_cases[i]);
			stats->total++;
		}
		err = cyaml_free(&cyaml_config, &test_file_schema, test_file,
				 0);
		if (err != CYAML_OK) {
			fprintf(stderr, "Error: '%s'\n", cyaml_strerror(err));
			stats->errors++;
			continue;
		}
	}

	return cases;
}

/// Runs runs all valid tests in the given @test_files
/// and returns the result as well as statistics in @stats.
TestRunResult run_tests(char **test_files, uint32_t file_count,
			TestRunStats *stats)
{
	TestCase **cases = parse_test_cases(test_files, file_count, stats);
	return get_test_run_result(stats);
}
