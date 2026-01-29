// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#define _XOPEN_SOURCE 500
#include "../../../utils.h"
#include "test_run.h"
#include <capstone/platform.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Pointer to the file list table
// Must be a thread local, because we cannot pass arguments to `nftw`.
// So the found test files can only be saved, very annoyingly,
// to a global/thread-local mutable variables.
char ***test_files = NULL;
uint32_t file_count = 0;

static void help(const char *self)
{
	fprintf(stderr, "%s <test-file-dir>/<test-file.yml> ...\n", self);
}

static int handle_ftree_entry(const char *fpath, const struct stat *sb,
			      int typeflag, struct FTW *ftwbuf)
{
	if (typeflag != FTW_F) {
		return 0;
	}
	const char *suffix = strstr(fpath, ".yaml");
	if (!suffix || suffix - fpath != strlen(fpath) - 5) {
		// Misses the .yaml suffix.
		return 0;
	}

	file_count++;
	*test_files = cs_mem_realloc(*test_files, sizeof(char *) * file_count);
	if (!*test_files) {
		fprintf(stderr, "[!] realloc failed\n");
		return -1;
	}
	test_files[0][file_count - 1] = cs_strdup(fpath);
	return 0;
}

/// Parses the test file paths from the @argv array.
static void get_tfiles(int argc, const char **argv)
{
	for (size_t i = 1; i < argc; ++i) {
		if (nftw(argv[i], handle_ftree_entry, 20,
			 FTW_DEPTH | FTW_PHYS) == -1) {
			fprintf(stderr, "[!] nftw failed.\n");
			return;
		}
	}
}

void print_test_run_stats(const TestRunStats *stats)
{
	printf("\n-----------------------------------------\n");
	printf("Test run statistics\n\n");
	printf("Valid files: %" PRId32 "\n", stats->valid_test_files);
	printf("Invalid files: %" PRId32 "\n", stats->invalid_files);
	printf("Errors: %" PRId32 "\n\n", stats->errors);
	printf("Test cases:\n");
	printf("\tTotal: %" PRId32 "\n", stats->tc_total);
	printf("\tSuccessful: %" PRId32 "\n", stats->successful);
	printf("\tSkipped: %" PRId32 "\n", stats->skipped);
	printf("\tFailed: %" PRId32 "\n", stats->failed);
	printf("\n\tDecoded instructions: %" PRId32 "\n", stats->decoded_insns);
	printf("-----------------------------------------\n");
	printf("\n");
}

void cleanup_test_files()
{
	if (!test_files) {
		return;
	}
	for (size_t k = 0; k < file_count; ++k) {
		cs_mem_free(test_files[0][k]);
	}
	if (test_files[0]) {
		cs_mem_free(test_files[0]);
	}
	cs_mem_free(test_files);
}

int main(int argc, const char **argv)
{
	if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		help(argv[0]);
		exit(EXIT_FAILURE);
	}
	test_files = malloc(sizeof(char **));
	*test_files = NULL;

	get_tfiles(argc, argv);
	if (!*test_files || file_count == 0) {
		fprintf(stderr, "Arguments are invalid. No files found.\n");
		cleanup_test_files();
		exit(EXIT_FAILURE);
	}

	printf("Test files found: %" PRId32 "\n", file_count);
	TestRunStats stats = { 0 };
	TestRunResult res = cstest_run_tests(*test_files, file_count, &stats);

	print_test_run_stats(&stats);
	cleanup_test_files();
	if (res == TEST_RUN_ERROR) {
		fprintf(stderr, "[!] An error occured.\n");
		exit(EXIT_FAILURE);
	} else if (res == TEST_RUN_SUCCESS) {
		printf("[o] All tests succeeded.\n");
		exit(EXIT_SUCCESS);
	} else if (res == TEST_RUN_FAILURE) {
		printf("\nNOTE: Asserts have the actual data on the left side: 'actual' != 'expected'\n\n");
		fprintf(stderr, "[!] Some tests failed.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "[!] Unhandled Test Run result\n");
	exit(EXIT_FAILURE);
}
