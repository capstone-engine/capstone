// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include "test_mappings.h"
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
		for (size_t k = 0; k < test_file_data->test_cases_count;
		     ++k, stats->total++) {
			cases[stats->total] =
				test_case_clone(&test_file_data->test_cases[k]);
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

static bool parse_input_options(const TestInput *input, cs_arch *arch,
				cs_mode *mode, cs_opt *opt_arr,
				size_t opt_arr_size,
				size_t *opt_set)
{
	assert(input && arch && mode && opt_arr);
	bool arch_found = false;
	const char *opt_str = input->arch;
	for (size_t i = 0; i < ARR_SIZE(test_arch_map); i++) {
		if (strcmp(opt_str, test_arch_map[i].str) == 0) {
			*arch = test_arch_map[i].arch;
			arch_found = true;
			break;
		}
	}
	if (!arch_found) {
		fprintf(stderr, "[!] '%s' is not mapped to a capstone architecture.\n", input->arch);
		return false;
	}
	size_t opt_idx = 0;
	bool mode_found = false;
	char **options = input->options;
	for (size_t i = 0; i < input->options_count; ++i) {
		opt_str = options[i];
		for (size_t k = 0; k < ARR_SIZE(test_mode_map) || k < ARR_SIZE(test_option_map); k++) {
			if (k < ARR_SIZE(test_mode_map) && strcmp(opt_str, test_mode_map[k].str) == 0) {
				*mode |= test_mode_map[k].mode;
				mode_found = true;
				continue;
			}
			if (k < ARR_SIZE(test_option_map) && strcmp(opt_str, test_option_map[k].str) == 0) {
				if (opt_idx >= opt_arr_size) {
					fprintf(stderr, "Too many options given in: '%s'. Maximum is: %" PRId64 "\n", opt_str, opt_arr_size);
					return false;
				}
				opt_arr[opt_idx++] = test_option_map[k].opt;
				continue;
			}
		}
	}
	*opt_set = opt_idx;
	if (!mode_found) {
		*mode = 0;
	}
	return true;
}

/// Parses the options for cs_open/cs_option and initializes the handle.
/// Returns true for success and false otherwise.
static bool open_cs_handle(UnitTestState *ustate)
{
	cs_arch arch = 0;
	cs_mode mode = 0;
	cs_opt options[8] = { 0 };
	size_t options_set = 0;

	if (!parse_input_options(ustate->tcase->input, &arch, &mode, options,
				 8, &options_set)) {
		char *tc_str = test_input_stringify(ustate->tcase->input, "");
		fprintf(stderr, "Could not parse options: %s\n",
			 tc_str);
		cs_mem_free(tc_str);
	}

	cs_err err = cs_open(arch, mode, &ustate->handle);
	if (err != CS_ERR_OK) {
		char *tc_str = test_input_stringify(ustate->tcase->input, "");
		fprintf(stderr, "[!] cs_open() failed with: '%s'. TestInput: %s\n",
			 cs_strerror(err), tc_str);
		cs_mem_free(tc_str);
		return false;
	}
	for (size_t i = 0; i < options_set; ++i) {
		err = cs_option(ustate->handle, options[i].type, options[i].val);
		if (err != CS_ERR_OK) {
			char *tc_str = test_input_stringify(ustate->tcase->input, "");
			fprintf(stderr, "[!] cs_option() failed with: '%s'. TestInput: %s\n",
				 cs_strerror(err), tc_str);
			cs_mem_free(tc_str);
			return false;
		}
	}
	return true;
}

static int cstest_unit_test_setup(void **state)
{
	assert(state);
	UnitTestState *ustate = *state;
	assert(ustate->tcase);
	if (!open_cs_handle(ustate)) {
		fail_msg("Failed to initialize capston with given options.");
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
	assert(ustate->tcase);
	csh handle = ustate->handle;
	TestCase *tcase = ustate->tcase;

	cs_insn *insns = NULL;
	size_t insns_count = cs_disasm(handle, tcase->input->bytes,
				       tcase->input->bytes_count,
				       tcase->input->address, 0, &insns);
	test_expected_compare(tcase->expected, insns, insns_count);
	cs_free(insns, insns_count);
}

static void eval_test_cases(TestCase **test_cases, TestRunStats *stats)
{
	assert(test_cases && stats);
	// CMocka's API doesn't allow to init a CMUnitTest with a partially initialized state
	// (which is later initialized in the test setup).
	// So we do it manually here.
	struct CMUnitTest *utest_table =
		cs_mem_calloc(sizeof(struct CMUnitTest), stats->total);

	char utest_id[16] = { 0 };

	for (size_t i = 0; i < stats->total; ++i) {
		UnitTestState *ut_state = cs_mem_calloc(sizeof(UnitTestState), 1);
		ut_state->tcase = test_cases[i];

		cs_snprintf(utest_id, sizeof(utest_id), "%" PRIx32 ": ", i);
		utest_table[i].name = test_input_stringify(ut_state->tcase->input, utest_id);
		utest_table[i].initial_state = ut_state;
		utest_table[i].setup_func = cstest_unit_test_setup;
		utest_table[i].teardown_func = cstest_unit_test_teardown;
		utest_table[i].test_func = cstest_unit_test;
	}
	// Use private function here, because the API takes only constant tables.
	int failed_tests = _cmocka_run_group_tests(
		"All test cases", utest_table, stats->total, NULL, NULL);
	for (size_t i = 0; i < stats->total; ++i) {
		cs_mem_free((char *) utest_table[i].name);
		cs_mem_free(utest_table[i].initial_state);
	}
	cs_mem_free(utest_table);
	stats->failed += failed_tests;
	stats->successful += stats->total - failed_tests;
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
