// Copyright © 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: BSD-3

#include "../../include/capstone/capstone.h"
#include "unit_test.h"
#include <stdio.h>
#include <string.h>

static bool test_cs_mem_setup_fail()
{
	printf("Test test_cs_mem_setup_fail\n");
	cs_opt_mem mem = { .malloc = malloc,
			   .calloc = calloc,
			   .realloc = realloc,
			   .free = free,
			   .vsnprintf = NULL };
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.vsnprintf = vsnprintf;
	mem.malloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.malloc = malloc;
	mem.calloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.calloc = calloc;
	mem.realloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.realloc = realloc;
	mem.free = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);

	return true;
}

int main()
{
	bool result = true;
	result &= test_cs_mem_setup_fail();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
