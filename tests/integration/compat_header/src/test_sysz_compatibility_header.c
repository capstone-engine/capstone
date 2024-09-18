// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3.0-Clause

#include <stdio.h>
#include <inttypes.h>

#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#include <capstone/capstone.h>

 // 0  5a 0f 1f ff        a	%r0, 0xfff(%r15,%r1)
	// ID: 1 (a)
	// op_count: 2
	// 	operands[0].type: REG = r0
	// 	operands[0].access: WRITE
	// 	operands[1].type: MEM
	// 		operands[1].mem.base: REG = r1
	// 		operands[1].mem.index: REG = r15
	// 		operands[1].mem.disp: 0xfff
	// 		operands[1].mem.am: SYSTEMZ_AM_BDX
	// 	operands[1].access: READ


int sysz(void)
{
	printf("\nSYSZ\n\n");
	csh handle;

	if (cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return -1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	uint8_t bytes[] = { 0x5a, 0x0f, 0x1f, 0xff };
	size_t count =
		cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &insn);
	if (count != 1) {
		fprintf(stderr, "Failed to disassemble code.\n");
		goto err;
	}
	printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[0].address, insn[0].mnemonic,
	       insn[0].op_str);
	printf("A register = %s\n",
	       cs_reg_name(handle, insn[0].detail->sysz.operands[0].reg));
	printf("An mem am = %" PRId32 "\n",
	       insn[0].detail->sysz.operands[1].mem.am);
	printf("An mem disp = %" PRId64 "\n",
	       insn[0].detail->sysz.operands[1].mem.disp);
	printf("Mem base = %s\n",
	       cs_reg_name(handle, insn[0].detail->sysz.operands[1].mem.base));
	printf("Mem index = %s\n",
	       cs_reg_name(handle, insn[0].detail->sysz.operands[1].mem.index));

	if (insn[0].address != 0x1000) {
		fprintf(stderr, "Address wrong.\n");
		goto err;
	}
	if (strcmp(insn[0].mnemonic, "a") != 0) {
		fprintf(stderr, "Mnemonic wrong.\n");
		goto err;
	}
	if (strcmp(insn[0].op_str, "%r0, 0xfff(%r15,%r1)") != 0) {
		fprintf(stderr, "op_str wrong.\n");
		goto err;
	}
	if (strcmp(cs_reg_name(handle, insn[0].detail->sysz.operands[0].reg),
		   "r0") != 0) {
		fprintf(stderr, "register wrong.\n");
		goto err;
	}
	if (((sysz_addr_mode) insn[0].detail->sysz.operands[1].mem.am) != SYSZ_AM_BDX) {
		fprintf(stderr, "mem.am wrong\n");
		goto err;
	}
	if (insn[0].detail->sysz.operands[1].mem.disp != 0xfff) {
		fprintf(stderr, "mem.disp wrong\n");
		goto err;
	}
	if (strcmp(cs_reg_name(handle, insn[0].detail->sysz.operands[1].mem.base), "r1") != 0) {
		fprintf(stderr, "mem.base wrong\n");
		goto err;
	}
	if (strcmp(cs_reg_name(handle, insn[0].detail->sysz.operands[1].mem.index), "r15") != 0) {
		fprintf(stderr, "mem.index wrong\n");
		goto err;
	}

	cs_free(insn, count);
	cs_close(&handle);
	return 0;

err:
	printf("ERROR: Failed to disassemble given code corrcetly!\n");
	cs_free(insn, count);
	cs_close(&handle);
	return -1;
}
#undef CAPSTONE_SYSTEMZ_COMPAT_HEADER
