#include "unit_test.h"
#include <capstone/capstone.h>
#include <stdio.h>

/* Regression test for issue 3162: cs_option(handle, CS_OPT_MODE, CS_MODE_ARM)
 * returned CS_ERR_OK but the handle stayed in Thumb mode.
 * ARMModule.c used `handle->mode |= value`, so CS_MODE_ARM (0) was a no-op. */

static bool test_arm_mode_switch()
{
	printf("Test test_arm_mode_switch\n");
	static const uint8_t code[] = {0x02, 0xc6, 0x8f, 0xe2}; /* add r12, pc, #0x200000 */

	csh handle;
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
		return false;
	}

	cs_insn *insn = NULL;

	size_t count = cs_disasm(handle, code, sizeof(code), 0xb7f4, 1, &insn);
	CHECK_INT_EQUAL_RET_FALSE(count, 1);
	CHECK_INT_EQUAL_RET_FALSE((size_t)insn[0].size, 4);
	cs_free(insn, count);

	/* ARM -> Thumb */
	if (cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB) != CS_ERR_OK) {
		cs_close(&handle);
		return false;
	}
	count = cs_disasm(handle, code, sizeof(code), 0xb7f4, 1, &insn);
	CHECK_INT_EQUAL_RET_FALSE(count, 1);
	CHECK_INT_EQUAL_RET_FALSE((size_t)insn[0].size, 2);
	cs_free(insn, count);

	/* Thumb -> ARM (the case that failed before the fix) */
	if (cs_option(handle, CS_OPT_MODE, CS_MODE_ARM) != CS_ERR_OK) {
		cs_close(&handle);
		return false;
	}
	count = cs_disasm(handle, code, sizeof(code), 0xb7f4, 1, &insn);
	CHECK_INT_EQUAL_RET_FALSE(count, 1);
	CHECK_INT_EQUAL_RET_FALSE((size_t)insn[0].size, 4);
	CHECK_STR_EQUAL_RET_FALSE(insn[0].mnemonic, "add");
	cs_free(insn, count);

	/* Thumb -> Thumb from a fresh thumb handle still works */
	if (cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB) != CS_ERR_OK) {
		cs_close(&handle);
		return false;
	}
	count = cs_disasm(handle, code, sizeof(code), 0xb7f4, 1, &insn);
	CHECK_INT_EQUAL_RET_FALSE(count, 1);
	CHECK_INT_EQUAL_RET_FALSE((size_t)insn[0].size, 2);
	cs_free(insn, count);

	cs_close(&handle);
	return true;
}

int main()
{
	if (!test_arm_mode_switch()) {
		printf("test_arm_mode_switch FAILED\n");
		return 1;
	}
	printf("test_arm_mode_switch OK\n");
	return 0;
}
