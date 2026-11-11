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

#ifdef CAPSTONE_HAS_X86
static bool test_cs_detail_off()
{
	printf("Test test_cs_detail_off\n");
	csh handle;
	CHECK_INT_EQUAL_RET_FALSE(
		(size_t)cs_open(CS_ARCH_X86, CS_MODE_64, &handle), CS_ERR_OK);
	const cs_opt_value options[] = { CS_OPT_ON, CS_OPT_OFF, CS_OPT_ON };
	for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		CHECK_INT_EQUAL_RET_FALSE(
			(size_t)cs_option(handle, CS_OPT_DETAIL, options[i]),
			CS_ERR_OK);
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return false;
		CHECK_INT_EQUAL_RET_FALSE((size_t)(insn->detail != NULL),
					  options[i] == CS_OPT_ON);
		cs_free(insn, 1);
	}
	cs_close(&handle);
	return true;
}
#endif

int main()
{
	bool result = true;
#ifdef CAPSTONE_HAS_X86
	result &= test_cs_detail_off();
#endif
	result &= test_cs_mem_setup_fail();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
