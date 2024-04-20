// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3.0-Clause

#include <stdio.h>
#include <inttypes.h>

#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

int main(void)
{
	csh handle;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
		printf("cs_open failed\n");
		return -1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	uint8_t bytes[] = "0x1a,0x48,0xa0,0xf8";
	size_t count = cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &insn);
	if (count > 0) {
		printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address,
		       insn[0].mnemonic, insn[0].op_str);
		printf("A register = %s\n", cs_reg_name(handle, insn[0].detail->arm64.operands[0].reg));
		printf("An imm = 0x%" PRIx64 "\n", insn[0].detail->arm64.operands[1].imm);

		cs_free(insn, count);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
		cs_close(&handle);
		return -1;
	}

	cs_close(&handle);

	return 0;
}
