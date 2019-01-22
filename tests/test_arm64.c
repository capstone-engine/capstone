/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013 */

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
	cs_arm64 *arm64;
	int i;
	cs_regs regs_read, regs_write;
	unsigned char regs_read_count, regs_write_count;
	unsigned char access;

	// detail can be NULL if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm64 = &(ins->detail->arm64);
	if (arm64->op_count)
		printf("\top_count: %u\n", arm64->op_count);

	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &(arm64->operands[i]);
		switch(op->type) {
			default:
				break;
			case ARM64_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case ARM64_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
				break;
			case ARM64_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != ARM64_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != ARM64_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case ARM64_OP_CIMM:
				printf("\t\toperands[%u].type: C-IMM = %u\n", i, (int)op->imm);
				break;
			case ARM64_OP_REG_MRS:
				printf("\t\toperands[%u].type: REG_MRS = 0x%x\n", i, op->reg);
				break;
			case ARM64_OP_REG_MSR:
				printf("\t\toperands[%u].type: REG_MSR = 0x%x\n", i, op->reg);
				break;
			case ARM64_OP_PSTATE:
				printf("\t\toperands[%u].type: PSTATE = 0x%x\n", i, op->pstate);
				break;
			case ARM64_OP_SYS:
				printf("\t\toperands[%u].type: SYS = 0x%x\n", i, op->sys);
				break;
			case ARM64_OP_PREFETCH:
				printf("\t\toperands[%u].type: PREFETCH = 0x%x\n", i, op->prefetch);
				break;
			case ARM64_OP_BARRIER:
				printf("\t\toperands[%u].type: BARRIER = 0x%x\n", i, op->barrier);
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

		if (op->shift.type != ARM64_SFT_INVALID &&
				op->shift.value)
			printf("\t\t\tShift: type = %u, value = %u\n",
					op->shift.type, op->shift.value);

		if (op->ext != ARM64_EXT_INVALID)
			printf("\t\t\tExt: %u\n", op->ext);

		if (op->vas != ARM64_VAS_INVALID)
			printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op->vas);

		if (op->vess != ARM64_VESS_INVALID)
			printf("\t\t\tVector Element Size Specifier: %u\n", op->vess);

		if (op->vector_index != -1)
			printf("\t\t\tVector Index: %u\n", op->vector_index);
	}

	if (arm64->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm64->writeback)
		printf("\tWrite-back: True\n");

	if (arm64->cc)
		printf("\tCode-condition: %u\n", arm64->cc);

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
//#define ARM64_CODE "\xe1\x0b\x40\xb9"	// ldr		w1, [sp, #0x8]
//#define ARM64_CODE "\x21\x7c\x00\x53"	// lsr	w1, w1, #0x0
//#define ARM64_CODE "\x21\x7c\x02\x9b"
//#define ARM64_CODE "\x20\x04\x81\xda"	// csneg	x0, x1, x1, eq | cneg x0, x1, ne
//#define ARM64_CODE "\x20\x08\x02\x8b"		// add	x0, x1, x2, lsl #2

//#define ARM64_CODE "\x20\xcc\x20\x8b"
//#define ARM64_CODE "\xe2\x8f\x40\xa9"	// ldp	x2, x3, [sp, #8]
//#define ARM64_CODE "\x20\x40\x60\x1e"	// fmov d0, d1
//#define ARM64_CODE "\x20\x7c\x7d\x93"	// sbfiz	x0, x1, #3, #32

//#define ARM64_CODE "\x20\x88\x43\xb3"	// bfxil	x0, x1, #3, #32
//#define ARM64_CODE "\x01\x71\x08\xd5"	// sys	#0, c7, c1, #0, x1
//#define ARM64_CODE "\x00\x71\x28\xd5"	// sysl	x0, #0, c7, c1, #0

//#define ARM64_CODE "\x20\xf4\x18\x9e"	// fcvtzs	x0, s1, #3
//#define ARM64_CODE "\x20\x74\x0b\xd5"	// dc	zva, x0: FIXME: handle as "sys" insn
//#define ARM64_CODE "\x00\x90\x24\x1e"	// fmov s0, ##10.00000000
//#define ARM64_CODE "\xe1\x0b\x40\xb9"	// ldr		w1, [sp, #0x8]
//#define ARM64_CODE "\x20\x78\x62\xf8"	// ldr x0, [x1, x2, lsl #3]
//#define ARM64_CODE "\x41\x14\x44\xb3"	// bfm	x1, x2, #4, #5
//#define ARM64_CODE "\x80\x23\x29\xd5"	// sysl	x0, #1, c2, c3, #4
//#define ARM64_CODE "\x20\x00\x24\x1e"	// fcvtas	w0, s1
//#define ARM64_CODE "\x41\x04\x40\xd2"	// eor	x1, x2, #0x3
//#define ARM64_CODE "\x9f\x33\x03\xd5"	// 	dsb	osh
//#define ARM64_CODE "\x41\x10\x23\x8a"	// bic	x1, x2, x3, lsl #4
//#define ARM64_CODE "\x16\x41\x3c\xd5"	// mrs	x22, sp_el1
//#define ARM64_CODE "\x41\x1c\x63\x0e"	// bic	v1.8b, v2.8b, v3.8b
//#define ARM64_CODE "\x41\xd4\xe3\x6e"	// fabd	v1.2d, v2.2d, v3.2d
//#define ARM64_CODE "\x20\x8c\x62\x2e"	// cmeq	v0.4h, v1.4h, v2.4h
//#define ARM64_CODE "\x20\x98\x20\x4e"	// cmeq	v0.16b, v1.16b, #0
//#define ARM64_CODE "\x20\x2c\x05\x4e"	// smov	x0, v1.b[2]
//#define ARM64_CODE "\x21\xe4\x00\x2f"	// movi d1, #0xff
//#define ARM64_CODE "\x60\x78\x08\xd5"	// at	s1e0w, x0	// FIXME: same problem with dc ZVA
//#define ARM64_CODE "\x20\x00\xa0\xf2"	// movk	x0, #1, lsl #16
//#define ARM64_CODE "\x20\x08\x00\xb1"	// adds	x0, x1, #0x2
//#define ARM64_CODE "\x41\x04\x00\x0f"	// movi v1.2s, #0x2
//#define ARM64_CODE "\x06\x00\x00\x14"	// b 0x44
//#define ARM64_CODE "\x00\x90\x24\x1e"	// fmov s0, ##10.00000000
//#define ARM64_CODE "\x5f\x3f\x03\xd5"	// clrex
//#define ARM64_CODE "\x5f\x3e\x03\xd5"	// clrex #14
//#define ARM64_CODE "\x20\x00\x02\xab"	// adds	 x0, x1, x2 (alias of adds x0, x1, x2, lsl #0)
//#define ARM64_CODE "\x20\xf4\x18\x9e"	// fcvtzs	x0, s1, #3
//#define ARM64_CODE "\x20\xfc\x02\x9b"	// mneg	x0, x1, x2
//#define ARM64_CODE "\xd0\xb6\x1e\xd5"	// msr	s3_6_c11_c6_6, x16

//#define ARM64_CODE "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

//#define ARM64_CODE "\x09\x00\x38\xd5"	// DBarrier
//#define ARM64_CODE "\x20\xe4\x3d\x0f\xa2\x00\xae\x9e"
//#define ARM64_CODE "\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5"	// DBarrier
//#define ARM64_CODE "\x10\x5b\xe8\x3c"
//#define ARM64_CODE "\x00\x18\xa0\x5f\xa2\x00\xae\x9e"

#define ARM64_CODE "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"

	struct platform platforms[] = {
		{
			CS_ARCH_ARM64,
			CS_MODE_ARM,
			(unsigned char *)ARM64_CODE,
			sizeof(ARM64_CODE) - 1,
			"ARM-64"
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

int main()
{
	test();

	return 0;
}

