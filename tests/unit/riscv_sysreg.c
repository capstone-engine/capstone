#include "unit_test.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <inttypes.h>

static bool test_riscv_sysreg()
{
	printf("Test test_riscv_sysreg\n");
	// csrr a0, sstatus (0x10002573)
	// csrr a0, mtvec   (0x30502573)
	// csrr a0, mcause  (0x34202573)
	static const uint8_t code[] = {
		0x73, 0x25, 0x00, 0x10, 0x73, 0x25,
		0x50, 0x30, 0x73, 0x25, 0x20, 0x34,
	};
	static const uint16_t expected_sysregs[] = {
		RISCV_SYSREG_SSTATUS,
		RISCV_SYSREG_MTVEC,
		RISCV_SYSREG_MCAUSE,
	};

	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
		return false;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *insn;
	size_t count = cs_disasm(handle, code, sizeof(code), 0, 0, &insn);

	if (count != 3) {
		cs_close(&handle);
		return false;
	}

	for (size_t i = 0; i < count; i++) {
		cs_riscv *riscv = &insn[i].detail->riscv;
		bool found_sysreg = false;
		for (size_t j = 0; j < riscv->op_count; j++) {
			if (riscv->operands[j].type == RISCV_OP_CSR) {
				CHECK_INT_EQUAL_RET_FALSE(
					(size_t)riscv->operands[j].csr,
					(int32_t)expected_sysregs[i]);
				found_sysreg = true;

				switch (riscv->operands[j].csr) {
				case RISCV_SYSREG_SSTATUS:
					printf("  Found SSTATUS\n");
					break;
				case RISCV_SYSREG_MTVEC:
					printf("  Found MTVEC\n");
					break;
				case RISCV_SYSREG_MCAUSE:
					printf("  Found MCAUSE\n");
					break;
				default:
					printf("  Found other sysreg: 0x%x\n",
					       riscv->operands[j].csr);
					break;
				}
			}
		}
		if (!found_sysreg) {
			printf("  CSR operand not found in instruction %zu\n",
			       i);
			cs_free(insn, count);
			cs_close(&handle);
			return false;
		}
	}

	cs_free(insn, count);
	cs_close(&handle);
	return true;
}

int main(void)
{
	if (test_riscv_sysreg()) {
		return 0;
	} else {
		return 1;
	}
}
