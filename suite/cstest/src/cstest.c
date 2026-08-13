// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#define _XOPEN_SOURCE 500
#include "../../../utils.h"
#include "test_run.h"
#include <capstone/platform.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void help(const char *self)
{
	fprintf(stderr, "%s <test-file-dir>/<test-file.yml> ...\n", self);
}

static bool ends_in_suffix(const char *path, const char *file_suffix)
{
	if (!path || !file_suffix) {
		return false;
	}
	size_t path_len = strlen(path);
	size_t suffix_len = strlen(file_suffix);
	if (path_len < suffix_len ||
	    strcmp(path + path_len - suffix_len, file_suffix) != 0) {
		return false;
	}
	return true;
}

/// 1 - file has wrong suffix, is skipped.
/// 0 - added file
/// -1 - error abort
static int add_yaml_file_path(const char *fpath, char ***test_files,
			      size_t *file_count, const char *file_suffix)
{
	if (!ends_in_suffix(fpath, file_suffix)) {
		// Skip
		return 1;
	}

	(*file_count)++;
	*test_files = cs_mem_realloc(*test_files, sizeof(char *) * *file_count);
	if (!*test_files) {
		fprintf(stderr, "[!] realloc failed\n");
		return -1;
	}
	test_files[0][*file_count - 1] = cs_strdup(fpath);
	return 0;
}

#ifdef _WIN32
#define STAT_PTR(sb) ((struct _stat *)sb)
static bool get_file_stat(const char *fpath, struct _stat *sb)
{
	if (_stat(fpath, sb) == -1) {
		fprintf(stderr, "[!] _stat failed.\n");
		return false;
	}
	return true;
}

#else
#define STAT_PTR(sb) ((struct stat *)sb)
static bool get_file_stat(const char *fpath, struct stat *sb)
{
	if (lstat(fpath, sb) == -1) {
		fprintf(stderr, "[!] lstat failed.\n");
		return false;
	}
	return true;
}
#endif

/// 1 - skip
/// 0 - valid file or dir
/// -1 - error abort
static int check_path(const struct dirent *dir, const char *fpath,
		      void /*struct stat OR struct _stat*/ *sb)
{
	if (dir && (strstr(dir->d_name, "..") || !strcmp(dir->d_name, "."))) {
		return 1;
	}

	if (!get_file_stat(fpath, sb)) {
		return -1;
	}

	if (!(S_ISDIR(STAT_PTR(sb)->st_mode) ||
	      S_ISREG(STAT_PTR(sb)->st_mode))) {
		// is not a directory nor a file.
		return 1;
	}
	return 0;
}

/// Iterates over all files in the given path and stores the paths to
/// test_files.
/// This is a minimalist function. It doesn't follow any links.
/// Any path with ".." in it is ignored.
static bool collect_yaml_tests(const char *path, char ***test_files,
			       size_t *file_count)
{
#ifdef _WIN32
	struct _stat sb;
#else
	struct stat sb;
#endif

	char *fpath = NULL;
	DIR *d = NULL;
	struct dirent *dir = NULL;
	d = opendir(path);
	if (!d) {
		if (check_path(dir, path, &sb) == 0 && S_ISREG(sb.st_mode)) {
			bool added =
				add_yaml_file_path(path, test_files, file_count,
						   ".yaml") == 0 ||
				add_yaml_file_path(path, test_files, file_count,
						   ".yml") == 0;
			if (added) {
				return true;
			}
		}
		fprintf(stderr,
			"[!] '%s' is not a yaml file neither a directory.\n",
			path);
		return false;
	}
	while ((dir = readdir(d)) != NULL) {
		size_t plen = strlen(path) + strlen(dir->d_name) + 1;
		fpath = cs_mem_calloc(plen + 1, sizeof(char));
		if (snprintf(fpath, plen + 1, "%s/%s", path, dir->d_name) !=
		    plen) {
			fprintf(stderr, "[!] snprintf failed.\n");
			goto error;
		}
		switch (check_path(dir, fpath, &sb)) {
		case 0:
			break;
		case 1:
			cs_mem_free(fpath);
			continue;
		default:
		case -1:
			goto error;
		}
		if (S_ISREG(sb.st_mode)) {
			if (add_yaml_file_path(fpath, test_files, file_count,
					       ".yaml") == -1) {
				fprintf(stderr,
					"[!] yaml file check failed.\n");
				goto error;
			}
			if (add_yaml_file_path(fpath, test_files, file_count,
					       ".yml") == -1) {
				fprintf(stderr, "[!] yml file check failed.\n");
				goto error;
			}
		} else if (S_ISDIR(sb.st_mode)) {
			if (!collect_yaml_tests(fpath, test_files,
						file_count)) {
				goto error;
			}
		}
		cs_mem_free(fpath);
	}
	if (closedir(d)) {
		fprintf(stderr, "[!] closedir on '%s' failed.\n", path);
		return false;
	}
	return true;
error:
	cs_mem_free(fpath);
	closedir(d);
	return false;
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

static void cleanup_test_files(char **test_files, size_t file_count)
{
	if (!test_files) {
		return;
	}
	for (size_t k = 0; k < file_count; ++k) {
		cs_mem_free(test_files[k]);
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
	char **test_files = cs_mem_malloc(sizeof(char **));
	if (!test_files) {
		return -1;
	}
	*test_files = NULL;
	size_t file_count = 0;

	for (size_t i = 1; i < argc; ++i) {
		if (!collect_yaml_tests(argv[i], &test_files, &file_count)) {
			cleanup_test_files(test_files, file_count);
			fprintf(stderr,
				"[!] An error occurred while collecting the test files.\n");
			exit(EXIT_FAILURE);
		}
	}
	if (!*test_files || file_count == 0) {
		fprintf(stderr, "Arguments are invalid. No files found.\n");
		cleanup_test_files(test_files, file_count);
		exit(EXIT_FAILURE);
	}

	printf("Test files found: %zu\n", file_count);
	TestRunStats stats = { 0 };
	TestRunResult res = cstest_run_tests(test_files, file_count, &stats);

	print_test_run_stats(&stats);
	cleanup_test_files(test_files, file_count);
	if (res == TEST_RUN_ERROR) {
		fprintf(stderr, "[!] An error occurred.\n");
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

#undef STAT_PTR
