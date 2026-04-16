#include "unit_test.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool test_reg_access(csh handle, const uint8_t *code, size_t code_size,
			    const uint16_t *expected_read,
			    size_t expected_read_count,
			    const uint16_t *expected_write,
			    size_t expected_write_count)
{
	cs_insn *insn;
	size_t count = cs_disasm(handle, code, code_size, 0, 1, &insn);
	if (count == 0) {
		printf("Failed to disassemble instruction\n");
		return false;
	}
	// debugging print, useful but noisy
	//printf("\n\n======================= TEST GOT INSTRUCTION TEXT: %s %s \n\n======================= (num operands: %d)\n",
	//       insn->mnemonic, insn->op_str, insn->detail->riscv.op_count);
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	cs_err err = cs_regs_access(handle, insn, regs_read, &regs_read_count,
				    regs_write, &regs_write_count);
	if (err != CS_ERR_OK) {
		printf("cs_regs_access failed with error: %d\n", err);
		cs_free(insn, count);
		return false;
	}

	bool success = true;
	if (regs_read_count != expected_read_count) {
		printf("Read count mismatch: expected %zu, got %u\n",
		       expected_read_count, regs_read_count);
		success = false;
	} else {
		for (size_t i = 0; i < expected_read_count; i++) {
			bool found = false;
			for (size_t j = 0; j < regs_read_count; j++) {
				if (regs_read[j] == expected_read[i]) {
					found = true;
					break;
				}
			}
			if (!found) {
				printf("Expected read register %d not found\n",
				       expected_read[i]);
				success = false;
			}
		}
	}

	if (regs_write_count != expected_write_count) {
		printf("Write count mismatch: expected %zu, got %u\n",
		       expected_write_count, regs_write_count);
		success = false;
	} else {
		for (size_t i = 0; i < expected_write_count; i++) {
			bool found = false;
			for (size_t j = 0; j < regs_write_count; j++) {
				if (regs_write[j] == expected_write[i]) {
					found = true;
					break;
				}
			}
			if (!found) {
				printf("Expected write register %d not found\n",
				       expected_write[i]);
				success = false;
			}
		}
	}

	cs_free(insn, count);
	return success;
}

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
		return 1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL | CS_OPT_ON);

	bool success[10];
	memset(success, true, sizeof(success));

	// addi a0, a1, 10 -> 0x00a58513
	printf("Test 0: Testing addi a0, a1, 10\n");
	uint8_t addi_code[] = { 0x13, 0x85, 0xa5, 0x00 };
	uint16_t addi_read[] = { RISCV_REG_X11 }; // a1
	uint16_t addi_write[] = { RISCV_REG_X10 }; // a0
	success[0] = test_reg_access(handle, addi_code, sizeof(addi_code),
				     addi_read, 1, addi_write, 1);
	// jalr ra, a1, 0 -> 0x000580e7 (rd=x1=ra, rs1=x11=a1, imm=0)
	printf("Test 1: Testing jalr ra, a1, 0\n");
	uint8_t jalr_code[] = { 0xe7, 0x80, 0x05, 0x00 };
	uint16_t jalr_read[] = { RISCV_REG_X11 };
	uint16_t jalr_write[] = { RISCV_REG_X1 }; // ra
	success[1] = test_reg_access(handle, jalr_code, sizeof(jalr_code),
				     jalr_read, 1, jalr_write, 1);
	// lb a0, 0(sp) -> 0x00010503
	printf("Test 2: Testing lb a0, 0(sp)\n");
	uint8_t lb_code[] = { 0x03, 0x05, 0x01, 0x00 };
	uint16_t lb_read[] = { RISCV_REG_X2 }; // sp
	uint16_t lb_write[] = { RISCV_REG_X10 };
	success[2] = test_reg_access(handle, lb_code, sizeof(lb_code), lb_read,
				     1, lb_write, 1);

	// c.addi a0, 10 -> 0x0529
	printf("Test 3: Testing c.addi a0, 10\n");
	uint8_t caddi_code[] = { 0x29, 0x05 };
	uint16_t caddi_read[] = { RISCV_REG_X10 }; // x10 is both read and write
	uint16_t caddi_write[] = { RISCV_REG_X10 };
	success[3] = test_reg_access(handle, caddi_code, sizeof(caddi_code),
				     caddi_read, 1, caddi_write, 1);

	// ecall -> 0x00000073
	printf("Test 4: Testing ecall\n");
	uint8_t ecall_code[] = { 0x73, 0x00, 0x00, 0x00 };
	success[4] = test_reg_access(handle, ecall_code, sizeof(ecall_code),
				     NULL, 0, NULL, 0);

	// csrrw a0, sstatus, a1 -> 0x10059533 (Wait, CSRRW is 0x10059573?)
	// 0x10059573: csrrw x10, sstatus, x11
	printf("Test 5: Testing csrrw a0, sstatus, a1\n");
	uint8_t csrrw_code[] = { 0x73, 0x95, 0x05, 0x10 };
	uint16_t csrrw_read[] = {
		RISCV_REG_X11
	}; // sstatus (CSR) should NOT be here
	uint16_t csrrw_write[] = { RISCV_REG_X10 };
	success[5] = test_reg_access(handle, csrrw_code, sizeof(csrrw_code),
				     csrrw_read, 1, csrrw_write, 1);

	cs_close(&handle);
	bool all_success = true;
	for (int i = 0; i < sizeof(success) / sizeof(success[0]); i++) {
		if (!success[i]) {
			printf("Test %d failed\n", i);
			all_success = false;
		}
	}
	return all_success ? 0 : 1;
}
