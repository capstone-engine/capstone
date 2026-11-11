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

static bool test_arm_mode_switch(void)
{
	if (!cs_support(CS_ARCH_ARM) || cs_support(CS_SUPPORT_DIET))
		return true;

	const struct {
		cs_mode mode;
		uint8_t code[4];
		uint16_t size;
		const char *mnemonic;
	} steps[] = {
		{ CS_MODE_THUMB, { 0x02, 0xc6, 0x8f, 0xe2 }, 2, "stm" },
		{ CS_MODE_THUMB, { 0xff, 0xff, 0xff, 0xff }, 2, ".byte" },
		{ CS_MODE_THUMB, { 0x08, 0xbf }, 2, "it" },
		{ CS_MODE_ARM, { 0x02, 0xc6, 0x8f, 0xe2 }, 4, "add" },
		{ CS_MODE_ARM, { 0xff, 0xff, 0xff, 0xff }, 4, ".byte" },
		{ CS_MODE_THUMB, { 0x00, 0xbf }, 2, "nop" },
		{ CS_MODE_THUMB | CS_MODE_MCLASS,
		  { 0x41, 0xfe, 0x00, 0x0f },
		  4,
		  "vpt.i8" },
		{ CS_MODE_ARM, { 0x02, 0xc6, 0x8f, 0xe2 }, 4, "add" },
		{ CS_MODE_THUMB | CS_MODE_MCLASS,
		  { 0xa8, 0xee, 0x48, 0x1f },
		  4,
		  "vmovlt.s8" },
	};
	csh handle;
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return false;
	bool result = cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) ==
		      CS_ERR_OK;
	for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i) {
		if (cs_option(handle, CS_OPT_MODE, steps[i].mode) !=
		    CS_ERR_OK) {
			result = false;
			break;
		}
		cs_insn *insn = NULL;
		size_t count = cs_disasm(handle, steps[i].code,
					 sizeof(steps[i].code), 0xb7f4, 1,
					 &insn);
		if (count != 1 || insn->size != steps[i].size ||
		    strcmp(insn->mnemonic, steps[i].mnemonic) != 0) {
			printf("ARM mode step %zu: expected %s (%u bytes), got %s (%u bytes)\n",
			       i, steps[i].mnemonic, steps[i].size,
			       count ? insn->mnemonic : "no instruction",
			       count ? insn->size : 0);
			result = false;
		}
		cs_free(insn, count);
	}
	return cs_close(&handle) == CS_ERR_OK && result;
}

int main()
{
	bool result = true;
	result &= test_arm_mode_switch();
	result &= test_cs_mem_setup_fail();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
