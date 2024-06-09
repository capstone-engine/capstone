// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#define _XOPEN_SOURCE 500
#include <capstone/platform.h>
#include "cstest.h"
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

// Pointer to the file list table
thread_local char ***test_files = NULL;
thread_local uint32_t file_count = 0;

static void help(const char *self)
{
	printf("%s <test-file-dir>/<test-file.yml> ...\n", self);
}

static int handle_ftree_entry(const char *fpath, const struct stat *sb, int typeflag,
		       struct FTW *ftwbuf)
{
	if (typeflag != FTW_F) {
		return 0;
	}
	file_count++;
	*test_files = realloc(*test_files, sizeof(char *) * file_count);
	if (!*test_files) {
		printf("realloc failed\n");
		return -1;
	}
	test_files[0][file_count - 1] = strdup(fpath);
	return 0;
}

/// Parses the test file paths from the @argv array.
static void get_tfiles(int argc, const char **argv)
{
	for (size_t i = 1; i < argc; ++i) {
		if (nftw(argv[i], handle_ftree_entry, 20,
			 FTW_DEPTH | FTW_PHYS) == -1) {
			printf("nftw failed.\n");
			return;
		}
	}
}

int main(int argc, const char **argv)
{
	if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		help(argv[0]);
		return EXIT_ERROR;
	}
	test_files = malloc(sizeof(char **));
	*test_files = NULL;

	get_tfiles(argc, argv);
	if (!*test_files || file_count == 0) {
		printf("Arguments are invalid. No files found.\n");
		return EXIT_ERROR;
	}
	printf("Test files: %" PRId32 "\n", file_count);

	return EXIT_SUCCESS;
}
