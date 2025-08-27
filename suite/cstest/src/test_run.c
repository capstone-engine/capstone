// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_run.h"
#include "test_case.h"
#include "test_mapping.h"
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
	if (stats->tc_total !=
	    stats->successful + stats->failed + stats->skipped) {
		fprintf(stderr,
			"[!] Inconsistent statistics: total != successful + failed + skipped\n");
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
static TestFile **parse_test_files(char **tf_paths, uint32_t path_count,
				   TestRunStats *stats)
{
	TestFile **files = NULL;
	stats->tc_total = 0;

	for (size_t i = 0; i < path_count; ++i) {
		TestFile *test_file_data = NULL;
		cyaml_err_t err = cyaml_load_file(
			tf_paths[i], &cyaml_config, &test_file_schema,
			(cyaml_data_t **)&test_file_data, NULL);

		if (err != CYAML_OK || !test_file_data) {
			fprintf(stderr, "[!] Failed to parse test file '%s'\n",
				tf_paths[i]);
			fprintf(stderr, "[!] Error: '%s'\n",
				!test_file_data && err == CYAML_OK ?
					"Empty file" :
					cyaml_strerror(err));
			stats->invalid_files++;
			stats->errors++;
			continue;
		}

		size_t k = stats->valid_test_files++;
		// Copy all test cases of a test file
		files = cs_mem_realloc(files, sizeof(TestFile *) *
						      stats->valid_test_files);

		files[k] = test_file_clone(test_file_data);
		assert(files[k]);
		stats->tc_total += files[k]->test_cases_count;
		files[k]->filename = strrchr(tf_paths[i], '/') ?
					     strdup(strrchr(tf_paths[i], '/')) :
					     strdup(tf_paths[i]);

		err = cyaml_free(&cyaml_config, &test_file_schema,
				 test_file_data, 0);
		if (err != CYAML_OK) {
			fprintf(stderr, "[!] Error: '%s'\n",
				cyaml_strerror(err));
			stats->errors++;
			continue;
		}
	}

	return files;
}

/// Parses the @input and saves the results in the other arguments.
static bool parse_input_options(const TestInput *input, cs_arch *arch,
				cs_mode *mode, cs_opt *opt_arr,
				size_t opt_arr_size, size_t *opt_set)
{
	assert(input && arch && mode && opt_arr);
	bool arch_found = false;
	const char *opt_str = input->arch;

	int val = enum_map_bin_search(test_arch_map, ARR_SIZE(test_arch_map),
				      opt_str, &arch_found);
	if (arch_found) {
		*arch = val;
	} else {
		fprintf(stderr,
			"[!] '%s' is not mapped to a capstone architecture.\n",
			input->arch);
		return false;
	}

	*mode = 0;
	size_t opt_idx = 0;
	char **options = input->options;
	for (size_t i = 0; i < input->options_count; ++i) {
		bool opt_found = false;
		opt_str = options[i];
		val = enum_map_bin_search(test_mode_map,
					  ARR_SIZE(test_mode_map), opt_str,
					  &opt_found);

		if (opt_found) {
			*mode |= val;
			continue;
		}

		// Might be an option descriptor
		for (size_t k = 0; k < ARR_SIZE(test_option_map); k++) {
			if (strings_match(opt_str, test_option_map[k].str)) {
				if (opt_idx >= opt_arr_size) {
					fprintf(stderr,
						"Too many options given in: '%s'. Maximum is: %" PRId64
						"\n",
						opt_str,
						(uint64_t)opt_arr_size);
					return false;
				}
				opt_arr[opt_idx++] = test_option_map[k].opt;
				opt_found = true;
				break;
			}
		}
		if (!opt_found) {
			fprintf(stderr, "[!] Option: '%s' not used\n", opt_str);
		}
	}
	*opt_set = opt_idx;
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

	if (!parse_input_options(ustate->tcase->input, &arch, &mode, options, 8,
				 &options_set)) {
		char *tc_str = test_input_stringify(ustate->tcase->input, "");
		fprintf(stderr, "Could not parse options: %s\n", tc_str);
		cs_mem_free(tc_str);
		return false;
	}

	cs_err err = cs_open(arch, mode, &ustate->handle);
	if (err != CS_ERR_OK) {
		char *tc_str = test_input_stringify(ustate->tcase->input, "");
		fprintf(stderr,
			"[!] cs_open() failed with: '%s'. TestInput: %s\n",
			cs_strerror(err), tc_str);
		cs_mem_free(tc_str);
		return false;
	}

	// The bit mode must be set, otherwise the numbers are
	// not normalized correctly in the asm-test comparison step.
	if (arch == CS_ARCH_AARCH64 || mode & CS_MODE_64) {
		ustate->arch_bits = 64;
	} else if (mode & CS_MODE_16) {
		ustate->arch_bits = 16;
	} else {
		ustate->arch_bits = 32;
	}

	for (size_t i = 0; i < options_set; ++i) {
		err = cs_option(ustate->handle, options[i].type,
				options[i].val);
		if (err != CS_ERR_OK) {
			goto option_error;
		}
	}
	return true;

option_error: {
	char *tc_str = test_input_stringify(ustate->tcase->input, "");
	fprintf(stderr, "[!] cs_option() failed with: '%s'. TestInput: %s\n",
		cs_strerror(err), tc_str);
	cs_mem_free(tc_str);
	cs_close(&ustate->handle);
	return false;
}
}

static int cstest_unit_test_setup(void **state)
{
	assert(state);
	UnitTestState *ustate = *state;
	assert(ustate->tcase);
	if (!open_cs_handle(ustate)) {
		fail_msg("Failed to initialize Capstone with given options.");
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
	test_expected_compare(&ustate->handle, tcase->expected, insns,
			      insns_count, ustate->arch_bits);
	ustate->decoded_insns += insns_count;
	cs_free(insns, insns_count);
}

static void eval_test_cases(TestFile **test_files, TestRunStats *stats)
{
	assert(test_files && stats);
	// CMocka's API doesn't allow to init a CMUnitTest with a partially initialized state
	// (which is later initialized in the test setup).
	// So we do it manually here.
	struct CMUnitTest *utest_table =
		cs_mem_calloc(sizeof(struct CMUnitTest),
			      stats->tc_total); // Number of test cases.

	char utest_id[128] = { 0 };

	size_t tci = 0;
	for (size_t i = 0; i < stats->valid_test_files; ++i) {
		TestCase **test_cases = test_files[i]->test_cases;
		const char *filename = test_files[i]->filename ?
					       test_files[i]->filename :
					       NULL;

		for (size_t k = 0; k < test_files[i]->test_cases_count;
		     ++k, ++tci) {
			cs_snprintf(utest_id, sizeof(utest_id),
				    "%s - TC #%" PRIx32 ": ", filename, k);
			if (test_cases[k]->skip) {
				char *tc_name = test_input_stringify(
					test_cases[k]->input, utest_id);
				fprintf(stderr, "SKIP: %s\nReason: %s\n",
					tc_name, test_cases[k]->skip_reason);
				cs_mem_free(tc_name);
				stats->skipped++;
				continue;
			}

			UnitTestState *ut_state =
				cs_mem_calloc(sizeof(UnitTestState), 1);
			ut_state->tcase = test_cases[k];
			utest_table[tci].name = test_input_stringify(
				ut_state->tcase->input, utest_id);
			utest_table[tci].initial_state = ut_state;
			utest_table[tci].setup_func = cstest_unit_test_setup;
			utest_table[tci].teardown_func =
				cstest_unit_test_teardown;
			utest_table[tci].test_func = cstest_unit_test;
		}
	}
	assert(tci == stats->tc_total);
	// Use private function here, because the API takes only constant tables.
	int failed_tests = _cmocka_run_group_tests(
		"All test cases", utest_table, stats->tc_total, NULL, NULL);
	assert(failed_tests >= 0 && "Faulty return value");

	for (size_t i = 0; i < stats->tc_total; ++i) {
		UnitTestState *ustate = utest_table[i].initial_state;
		if (!ustate) {
			// Skipped test case
			continue;
		}
		stats->decoded_insns += ustate->decoded_insns;
		cs_mem_free((char *)utest_table[i].name);
		cs_mem_free(utest_table[i].initial_state);
	}
	cs_mem_free(utest_table);
	stats->failed += failed_tests;
	stats->successful += stats->tc_total - failed_tests - stats->skipped;
}

/// Runs runs all valid tests in the given @test_files
/// and returns the result as well as statistics in @stats.
TestRunResult cstest_run_tests(char **test_file_paths, uint32_t path_count,
			       TestRunStats *stats)
{
	TestFile **files = parse_test_files(test_file_paths, path_count, stats);
	if (!files) {
		return get_test_run_result(stats);
	}
	eval_test_cases(files, stats);
	for (size_t i = 0; i < stats->valid_test_files; ++i) {
		test_file_free(files[i]);
	}
	cs_mem_free(files);

	return get_test_run_result(stats);
}
