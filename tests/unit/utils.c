// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "unit_test.h"
#include "../utils.h"
#include <stdio.h>
#include <string.h>

static bool test_str_append_no_realloc()
{
	printf("Test test_str_append_no_realloc\n");

	char str_a[] = "AAAA\0\0\0\0\0";
	char str_b[] = "BBBB";
	char str_c[] = "\0\0\0\0\0";

	CHECK_NULL_RET_FALSE(str_append(NULL, NULL));
	CHECK_NULL_RET_FALSE(str_append(str_a, NULL));
	CHECK_NULL_RET_FALSE(str_append(NULL, str_b));

	str_append_no_realloc(str_a, sizeof(str_a), str_c);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAA");

	str_append_no_realloc(str_a, sizeof(str_a), str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAABBBB");

	str_append_no_realloc(str_c, sizeof(str_c), str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_c, "BBBB");

	str_append_no_realloc(str_b, sizeof(str_b), str_c);
	CHECK_STR_EQUAL_RET_FALSE(str_b, "BBBB");

	return true;
}

static bool test_str_append()
{
	printf("Test test_str_append\n");
	char *str_a = NULL;
	char *str_b = NULL;
	CHECK_NULL_RET_FALSE(str_append(str_a, str_b));

	str_a = calloc(5, sizeof(char));
	memcpy(str_a, "AAAA", 5);
	CHECK_NULL_RET_FALSE(str_append(str_a, str_b));

	str_b = calloc(5, sizeof(char));
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAA");

	memcpy(str_b, "BBBB", 5);
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAABBBB");

	memset(str_a, 0, strlen(str_a) + 1);
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "BBBB");
	free(str_a);
	free(str_b);

	return true;
}

int main()
{
	bool result = true;
	result &= test_str_append();
	result &= test_str_append_no_realloc();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
