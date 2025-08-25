// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3.0-Clause

#include <stdio.h>
#include <inttypes.h>

#define CAPSTONE_ARM_COMPAT_HEADER
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

int arm64(void)
{
	printf("\nARM64\n\n");
	csh handle;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return -1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	uint8_t bytes[] = { 0x30, 0x78, 0x31, 0x61 };
	size_t count =
		cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &insn);
	if (count != 1) {
		fprintf(stderr, "Failed to disassemble code.\n");
		goto err;
	}
	printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
	       insn[0].op_str);
	printf("A register = %s\n",
	       cs_reg_name(handle, insn[0].detail->arm64.operands[0].reg));
	printf("An imm = 0x%" PRIx64 "\n",
	       insn[0].detail->arm64.operands[1].imm);

	if (insn[0].address != 0x1000) {
		fprintf(stderr, "Address wrong.\n");
		goto err;
	}
	if (strcmp(insn[0].mnemonic, "adr") != 0) {
		fprintf(stderr, "Mnemonic wrong.\n");
		goto err;
	}
	if (strcmp(insn[0].op_str, "x1, 0xf162d") != 0) {
		fprintf(stderr, "op_str wrong.\n");
		goto err;
	}
	if (strcmp(cs_reg_name(handle, insn[0].detail->arm64.operands[0].reg),
		   "x1") != 0) {
		fprintf(stderr, "register wrong.\n");
		goto err;
	}
	if (insn[0].detail->arm64.operands[1].imm != 0xf162d) {
		fprintf(stderr, "Immediate wrong.\n");
		goto err;
	}
	arm64_cc test_cc64 = insn[0].detail->arm64.cc + ARM64_CC_GE;
	arm_cc test_cc = insn[0].detail->arm.cc + ARM_CC_LE;
	printf("test_cc64 = %" PRId32 " test_cc = %" PRId32 "\n", test_cc64,
	       test_cc);

	arm64_vas test_vas =
		insn[0].detail->arm64.operands[0].vas + ARM64_VAS_16B;
	printf("test_vas = %" PRId32 "\n", test_vas);

	cs_free(insn, count);
	cs_close(&handle);
	return 0;

err:
	printf("ERROR: Failed to disassemble given code corrcetly!\n");
	cs_free(insn, count);
	cs_close(&handle);
	return -1;
}

#undef CAPSTONE_AARCH64_COMPAT_HEADER
