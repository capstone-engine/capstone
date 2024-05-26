// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3.0-Clause

#include <stdio.h>
#include <inttypes.h>

#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

int main(void)
{
	csh handle;
	int ret = 0;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
		printf("cs_open failed\n");
		return -1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_buffer *buffer = cs_buffer_new(0);
	uint8_t bytes[] = "0x1a,0x48,0xa0,0xf8";
	size_t count = cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, buffer);
	if (count > 0) {
		cs_insn *insn = buffer->insn;
		printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address,
		       insn[0].mnemonic, insn[0].op_str);
		printf("A register = %s\n", cs_reg_name(handle, insn[0].detail->arm64.operands[0].reg));
		printf("An imm = 0x%" PRIx64 "\n", insn[0].detail->arm64.operands[1].imm);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
		ret = -1;
	}

	cs_buffer_free(buffer);
	cs_close(&handle);

	return ret;
}
