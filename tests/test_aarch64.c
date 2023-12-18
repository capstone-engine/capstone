/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#include "capstone/aarch64.h"
#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
};

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static void print_insn_detail(cs_insn *ins)
{
	cs_aarch64 *aarch64;
	int i;
	cs_regs regs_read, regs_write;
	unsigned char regs_read_count, regs_write_count;
	unsigned char access;

	// detail can be NULL if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	aarch64 = &(ins->detail->aarch64);
	if (aarch64->op_count)
		printf("\top_count: %u\n", aarch64->op_count);

	for (i = 0; i < aarch64->op_count; i++) {
		cs_aarch64_op *op = &(aarch64->operands[i]);
		switch(op->type) {
		default:
			break;
		case AArch64_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
			break;
		case AArch64_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
			break;
		case AArch64_OP_FP:
#if defined(_KERNEL_MODE)
			// Issue #681: Windows kernel does not support formatting float point
			printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
			printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
			break;
		case AArch64_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != AArch64_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != AArch64_REG_INVALID)
				printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
			if (ins->detail->aarch64.post_index)
				printf("\t\t\tpost-indexed: true\n");

			break;
		case AArch64_OP_SME_MATRIX:
			printf("\t\toperands[%u].type: SME_MATRIX\n", i);
			printf("\t\toperands[%u].sme.type: %d\n", i, op->sme.type);

			if (op->sme.tile != AArch64_REG_INVALID)
				printf("\t\toperands[%u].sme.tile: %s\n", i, cs_reg_name(handle, op->sme.tile));
			if (op->sme.slice_reg != AArch64_REG_INVALID)
				printf("\t\toperands[%u].sme.slice_reg: %s\n", i, cs_reg_name(handle, op->sme.slice_reg));
			if (op->sme.slice_offset.imm != -1 || op->sme.slice_offset.imm_range.first != -1) {
				printf("\t\toperands[%u].sme.slice_offset: ", i);
				if (op->sme.has_range_offset)
					printf("%hhd:%hhd\n", op->sme.slice_offset.imm_range.first, op->sme.slice_offset.imm_range.offset);
				else
					printf("%d\n", op->sme.slice_offset.imm);
			}
			if (op->sme.slice_reg != AArch64_REG_INVALID || op->sme.slice_offset.imm != -1)
				printf("\t\toperands[%u].sme.is_vertical: %s\n", i, (op->sme.is_vertical ? "true" : "false"));
			break;
		case AArch64_OP_CIMM:
			printf("\t\toperands[%u].type: C-IMM = %u\n", i, (int)op->imm);
			break;
		case AArch64_OP_SYSREG:
			printf("\t\toperands[%u].type: SYS REG:\n", i);
			switch (op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AArch64_OP_REG_MRS:
				printf("\t\toperands[%u].subtype: REG_MRS = 0x%x\n", i, op->sysop.reg.sysreg);
				break;
			case AArch64_OP_REG_MSR:
				printf("\t\toperands[%u].subtype: REG_MSR = 0x%x\n", i, op->sysop.reg.sysreg);
				break;
			case AArch64_OP_TLBI:
				printf("\t\toperands[%u].subtype TLBI = 0x%x\n", i, op->sysop.reg.tlbi);
				break;
			case AArch64_OP_IC:
				printf("\t\toperands[%u].subtype IC = 0x%x\n", i, op->sysop.reg.ic);
				break;
			}
			break;
		case AArch64_OP_SYSALIAS:
			printf("\t\toperands[%u].type: SYS ALIAS:\n", i);
			switch (op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AArch64_OP_SVCR:
				if(op->sysop.alias.svcr == AArch64_SVCR_SVCRSM)
					printf("\t\t\toperands[%u].svcr: BIT = SM\n", i);
				else if(op->sysop.alias.svcr == AArch64_SVCR_SVCRZA)
					printf("\t\t\toperands[%u].svcr: BIT = ZA\n", i);
				else if(op->sysop.alias.svcr == AArch64_SVCR_SVCRSMZA)
					printf("\t\t\toperands[%u].svcr: BIT = SM & ZA\n", i);
				break;
			case AArch64_OP_AT:
				printf("\t\toperands[%u].subtype AT = 0x%x\n", i, op->sysop.alias.at);
				break;
			case AArch64_OP_DB:
				printf("\t\toperands[%u].subtype DB = 0x%x\n", i, op->sysop.alias.db);
				break;
			case AArch64_OP_DC:
				printf("\t\toperands[%u].subtype DC = 0x%x\n", i, op->sysop.alias.dc);
				break;
			case AArch64_OP_ISB:
				printf("\t\toperands[%u].subtype ISB = 0x%x\n", i, op->sysop.alias.isb);
				break;
			case AArch64_OP_TSB:
				printf("\t\toperands[%u].subtype TSB = 0x%x\n", i, op->sysop.alias.tsb);
				break;
			case AArch64_OP_PRFM:
				printf("\t\toperands[%u].subtype PRFM = 0x%x\n", i, op->sysop.alias.prfm);
				break;
			case AArch64_OP_SVEPRFM:
				printf("\t\toperands[%u].subtype SVEPRFM = 0x%x\n", i, op->sysop.alias.sveprfm);
				break;
			case AArch64_OP_RPRFM:
				printf("\t\toperands[%u].subtype RPRFM = 0x%x\n", i, op->sysop.alias.rprfm);
				break;
			case AArch64_OP_PSTATEIMM0_15:
				printf("\t\toperands[%u].subtype PSTATEIMM0_15 = 0x%x\n", i, op->sysop.alias.pstateimm0_15);
				break;
			case AArch64_OP_PSTATEIMM0_1:
				printf("\t\toperands[%u].subtype PSTATEIMM0_1 = 0x%x\n", i, op->sysop.alias.pstateimm0_1);
				break;
			case AArch64_OP_PSB:
				printf("\t\toperands[%u].subtype PSB = 0x%x\n", i, op->sysop.alias.psb);
				break;
			case AArch64_OP_BTI:
				printf("\t\toperands[%u].subtype BTI = 0x%x\n", i, op->sysop.alias.bti);
				break;
			case AArch64_OP_SVEPREDPAT:
				printf("\t\toperands[%u].subtype SVEPREDPAT = 0x%x\n", i, op->sysop.alias.svepredpat);
				break;
			case AArch64_OP_SVEVECLENSPECIFIER:
				printf("\t\toperands[%u].subtype SVEVECLENSPECIFIER = 0x%x\n", i, op->sysop.alias.sveveclenspecifier);
				break;
			}
			break;
		case AArch64_OP_SYSIMM:
			printf("\t\toperands[%u].type: SYS IMM:\n", i);
			switch(op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AArch64_OP_EXACTFPIMM:
				printf("\t\toperands[%u].subtype EXACTFPIMM = %d\n", i, op->sysop.imm.exactfpimm);
				break;
			case AArch64_OP_DBNXS:
				printf("\t\toperands[%u].subtype DBNXS = %d\n", i, op->sysop.imm.dbnxs);
				break;
			}
			break;
		}
		
		access = op->access;
		switch(access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}
		
		if (op->shift.type != AArch64_SFT_INVALID &&
			op->shift.value)
			printf("\t\t\tShift: type = %u, value = %u\n",
				   op->shift.type, op->shift.value);

		if (op->ext != AArch64_EXT_INVALID)
			printf("\t\t\tExt: %u\n", op->ext);

		if (op->vas != AArch64Layout_Invalid)
			printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op->vas);

		if (op->vector_index != -1)
			printf("\t\t\tVector Index: %u\n", op->vector_index);
	}

	if (aarch64->update_flags)
		printf("\tUpdate-flags: True\n");

	if (ins->detail->writeback)
		printf("\tWrite-back: True\n");

	if (aarch64->cc != AArch64CC_Invalid)
		printf("\tCode-condition: %u\n", aarch64->cc);

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(handle, ins,
				regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}

	printf("\n");
}

static void test()
{
#define AArch64_CODE "\x09\x00\x38\xd5" \
    "\xbf\x40\x00\xd5" \
    "\x0c\x05\x13\xd5" \
    "\x20\x50\x02\x0e" \
    "\x20\xe4\x3d\x0f" \
	"\x00\x18\xa0\x5f" \
	"\xa2\x00\xae\x9e" \
    "\x9f\x37\x03\xd5" \
	"\xbf\x33\x03\xd5" \
	"\xdf\x3f\x03\xd5" \
	"\x21\x7c\x02\x9b" \
	"\x21\x7c\x00\x53" \
	"\x00\x40\x21\x4b" \
	"\xe1\x0b\x40\xb9" \
	"\x20\x04\x81\xda" \
	"\x20\x08\x02\x8b" \
	"\x10\x5b\xe8\x3c" \
	"\xfd\x7b\xba\xa9" \
	"\xfd\xc7\x43\xf8"

	struct platform platforms[] = {
		{
			CS_ARCH_AARCH64,
			CS_MODE_ARM,
			(unsigned char *)AArch64_CODE,
			sizeof(AArch64_CODE) - 1,
			"AARCH64"
		},
	};

	uint64_t address = 0x2c;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code: ", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code: ", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			abort();
		}

		printf("\n");

		cs_close(&handle);
	}
}

int test_macros() {
	assert(CS_AARCH64(_INS_BL) == AArch64_INS_BL);
	assert(CS_AARCH64pre(CS_ARCH_) == CS_ARCH_AARCH64);
	assert(CS_AARCH64CC(_AL) == AArch64CC_AL);
	assert(CS_AARCH64_VL_(16B) == AArch64Layout_VL_16B);
	cs_detail detail = { 0 };
	CS_cs_aarch64() aarch64_detail = { 0 };
	detail.aarch64 = aarch64_detail;
	CS_aarch64_op() op = { 0 };
	detail.CS_aarch64_.operands[0] = op;
	CS_aarch64_reg() reg = 1;
	CS_aarch64_cc() cc = AArch64CC_AL;
	CS_aarch64_extender() aarch64_extender = AArch64_EXT_SXTB;
	CS_aarch64_shifter() aarch64_shifter = AArch64_SFT_LSL;
	CS_aarch64_vas() aarch64_vas = AArch64Layout_VL_16B;
	// Do something with them to prevent compiler warnings.
	return reg + cc + aarch64_extender + aarch64_shifter + aarch64_vas + detail.aarch64.cc;

}

int main()
{
	test();
	test_macros();

	return 0;
}
