// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "unit_test.h"
#include "../utils.h"
#include <stdio.h>
#include <string.h>

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
	char *result = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(result, "AAAA");

	memcpy(str_b, "BBBB", 5);
	result = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(result, "AAAABBBB");

	memset(str_a, 0, 5);
	result = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(result, "BBBB");
	free(str_a);
	free(str_b);

	return true;
}

int main()
{
	bool result = true;
	result &= test_str_append();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
