// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include "../../../utils.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static TestRunResult get_test_run_result(TestRunStats *stats)
{
	if (stats->total != stats->successful + stats->failed) {
		fprintf(stderr,
			"[!] Inconsistent statistics: total != successful + failed\n");
		stats->errors++;
		return TEST_RUN_ERROR;
	}

	if (stats->errors != 0) {
		return TEST_RUN_ERROR;
	} else if (stats->failed != 0) {
		return TEST_RUN_FAILURE;
	}
	return TEST_RUN_SUCCESS;
}

/// Extract all test cases from the given test files.
static TestCase **parse_test_cases(char **test_files, uint32_t file_count,
				   TestRunStats *stats)
{
	TestCase **cases = NULL;
	stats->total = 0;

	for (size_t i = 0; i < file_count; ++i) {
		TestFile *test_file_data = NULL;
		cyaml_err_t err = cyaml_load_file(
			test_files[i], &cyaml_config, &test_file_schema,
			(cyaml_data_t **)&test_file_data, NULL);
		if (err != CYAML_OK || !test_file_data) {
			fprintf(stderr, "[!] Failed to parse test file '%s'\n",
				test_files[i]);
			fprintf(stderr, "[!] Error: '%s'\n",
				!test_file_data && err == CYAML_OK ?
					"Empty file" :
					cyaml_strerror(err));
			stats->errors++;
			continue;
		}

		// Copy all test cases of a test file
		cases = cs_mem_realloc(
			cases, sizeof(TestCase *) *
				       (stats->total +
					test_file_data->test_cases_count));
		for (size_t i = 0; i < test_file_data->test_cases_count;
		     ++i, stats->total++) {
			cases[stats->total] =
				test_case_clone(&test_file_data->test_cases[i]);
			assert(cases[stats->total]);
		}
		err = cyaml_free(&cyaml_config, &test_file_schema,
				 test_file_data, 0);
		if (err != CYAML_OK) {
			fprintf(stderr, "[!] Error: '%s'\n", cyaml_strerror(err));
			stats->errors++;
			continue;
		}
	}

	return cases;
}

static int cstest_unit_test_setup(void **state)
{
	assert(state);
	UnitTestState *ustate = *state;
	assert(ustate->stats && ustate->tcase);
	// Setup cs handle
	cs_err err = cs_open(0, 0, &ustate->handle);
	if (err != CS_ERR_OK) {
		char *tc_str = test_input_stringify(ustate->tcase->input, "");
		fail_msg("cs_open() failed with: '%s'. TestInput: %s",
			 cs_strerror(err), tc_str);
		cs_mem_free(tc_str);
		return -1;
	}
	return 0;
}

static int cstest_unit_test_teardown(void **state)
{
	if (!state) {
		return 0;
	}
	UnitTestState *ustate = *state;
	if (ustate->handle) {
		cs_err err = cs_close(&ustate->handle);
		if (err != CS_ERR_OK) {
			fail_msg("cs_close() failed with: '%s'.",
				 cs_strerror(err));
			return -1;
		}
	}
	return 0;
}

static void cstest_unit_test(void **state)
{
	assert(state);
	UnitTestState *ustate = *state;
	assert(ustate);
	assert(ustate->handle);
	assert(ustate->stats);
	assert(ustate->tcase);
	csh handle = ustate->handle;
	TestRunStats *stats = ustate->stats;
	TestCase *tcase = ustate->tcase;

	cs_insn *insns = NULL;
	size_t insns_count = cs_disasm(handle, tcase->input->bytes,
				       tcase->input->bytes_count,
				       tcase->input->address, 0, &insns);
	if (test_expected_compare(tcase->expected, insns, insns_count)) {
		stats->successful++;
	} else {
		stats->failed++;
	}
	cs_free(insns, insns_count);
}

static void eval_test_cases(TestCase **test_cases, TestRunStats *stats)
{
	assert(test_cases && stats);
	// CMocka's API doesn't allow to init a CMUnitTest with a partially initialized state
	// (which is later initialized in the setup_test function).
	// So we do it manually here.
	struct CMUnitTest *utest_table =
		cs_mem_calloc(sizeof(struct CMUnitTest), stats->total);

	char utest_id[16] = { 0 };

	for (size_t i = 0; i < stats->total; ++i) {
		UnitTestState *ut_state = cs_mem_calloc(sizeof(UnitTestState), 1);
		ut_state->tcase = test_cases[i];
		ut_state->stats = stats;

		cs_snprintf(utest_id, sizeof(utest_id), "%" PRIx32 ": ", i);
		utest_table[i].name = test_input_stringify(ut_state->tcase->input, utest_id);
		utest_table[i].initial_state = ut_state;
		utest_table[i].setup_func = cstest_unit_test_setup;
		utest_table[i].teardown_func = cstest_unit_test_teardown;
		utest_table[i].test_func = cstest_unit_test;
	}
	// Use private function here, because the API takes only constant tables.
	_cmocka_run_group_tests("All test cases", utest_table, stats->total,
				NULL, NULL);
	for (size_t i = 0; i < stats->total; ++i) {
		cs_mem_free((char *) utest_table[i].name);
		cs_mem_free(utest_table[i].initial_state);
	}
	cs_mem_free(utest_table);
}

/// Runs runs all valid tests in the given @test_files
/// and returns the result as well as statistics in @stats.
TestRunResult cstest_run_tests(char **test_files, uint32_t file_count,
			       TestRunStats *stats)
{
	TestCase **cases = parse_test_cases(test_files, file_count, stats);
	eval_test_cases(cases, stats);
	for (size_t i = 0; i < stats->total; ++i) {
		test_case_free(cases[i]);
	}
	cs_mem_free(cases);

	return get_test_run_result(stats);
}
