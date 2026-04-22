#include "unit_test.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <inttypes.h>

// c.addi sp, -16 (2 ops) -> addi a0, a1, 1 (3 ops) -> c.addi sp, -16 (2 ops)
// Without RISCV_init_cs_detail(), op_count accumulates: 2, 5, 7
static bool test_riscv_op_count_no_stale()
{
	printf("Test test_riscv_op_count_no_stale\n");
	static const uint8_t code[] = {
		0x41, 0x11, // c.addi sp, -16
		0x13, 0x85, 0x15, 0x00, // addi a0, a1, 1
		0x41, 0x11, // c.addi sp, -16
	};
	static const int32_t expected_op_counts[] = { 2, 3, 2 };

	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		    &handle) != CS_ERR_OK) {
		return false;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL);
	cs_option(handle, CS_OPT_SYNTAX,
		  CS_OPT_SYNTAX_NO_ALIAS_TEXT |
			  CS_OPT_SYNTAX_NO_ALIAS_TEXT_COMPRESSED);
	cs_insn *insn = cs_malloc(handle);

	const uint8_t *start = code;
	size_t size = sizeof(code);
	uint64_t address = 0;
	size_t i = 0;

	while (cs_disasm_iter(handle, &start, &size, &address, insn)) {
		CHECK_INT_EQUAL_RET_FALSE((size_t)insn->detail->riscv.op_count,
					  expected_op_counts[i]);
		++i;
	}

	cs_free(insn, 1);
	cs_close(&handle);
	return true;
}

int main(void)
{
	bool ret = true;
	ret &= test_riscv_op_count_no_stale();
	return ret ? 0 : -1;
}
