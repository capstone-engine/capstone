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
	int syntax;
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

static void print_insn_detail(csh cs_handle, cs_insn *ins)
{
	cs_arm *arm;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm = &(ins->detail->arm);

	if (arm->op_count)
		printf("\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(cs_handle, op->reg));
				break;
			case ARM_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case ARM_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
				break;
			case ARM_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != ARM_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(cs_handle, op->mem.base));
				if (op->mem.index != ARM_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(cs_handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
				if (op->mem.lshift != 0)
					printf("\t\t\toperands[%u].mem.lshift: 0x%x\n", i, op->mem.lshift);

				break;
			case ARM_OP_PIMM:
				printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_CIMM:
				printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_SETEND:
				printf("\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE? "be" : "le");
				break;
			case ARM_OP_SYSREG:
				printf("\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
				break;
		}

		if (op->neon_lane != -1) {
			printf("\t\toperands[%u].neon_lane = %u\n", i, op->neon_lane);
		}

		switch(op->access) {
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

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				// shift with constant value
				printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			else
				// shift with register
				printf("\t\t\tShift: %u = %s\n", op->shift.type,
						cs_reg_name(cs_handle, op->shift.value));
		}

		if (op->vector_index != -1) {
			printf("\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
		}

		if (op->subtracted)
			printf("\t\tSubtracted: True\n");
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		printf("\tCode condition: %u\n", arm->cc);

	if (arm->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm->writeback)
		printf("\tWrite-back: True\n");

	if (arm->cps_mode)
		printf("\tCPSI-mode: %u\n", arm->cps_mode);

	if (arm->cps_flag)
		printf("\tCPSI-flag: %u\n", arm->cps_flag);

	if (arm->vector_data)
		printf("\tVector-data: %u\n", arm->vector_data);

	if (arm->vector_size)
		printf("\tVector-size: %u\n", arm->vector_size);

	if (arm->usermode)
		printf("\tUser-mode: True\n");

	if (arm->mem_barrier)
		printf("\tMemory-barrier: %u\n", arm->mem_barrier);

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(cs_handle, ins,
				regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(cs_handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(cs_handle, regs_write[i]));
			}
			printf("\n");
		}
	}

	printf("\n");
}

static void test()
{
//#define ARM_CODE "\x04\xe0\x2d\xe5"	// str	lr, [sp, #-0x4]!
//#define ARM_CODE "\xe0\x83\x22\xe5"	// str	r8, [r2, #-0x3e0]!
//#define ARM_CODE "\xf1\x02\x03\x0e"	// mcreq	p0x2, #0x0, r0, c0x3, c0x1, #0x7
//#define ARM_CODE "\x00\x00\xa0\xe3"	// mov	r0, #0x0 
//#define ARM_CODE "\x02\x30\xc1\xe7"	// strb	r3, [r1, r2]
//#define ARM_CODE "\x00\x00\x53\xe3"	// cmp	r3, #0x0
//#define ARM_CODE "\x02\x00\xa1\xe2"	// adc r0, r1, r2
//#define ARM_CODE "\x21\x01\xa0\xe0"	// adc	r0, r0, r1, lsr #2
//#define ARM_CODE "\x21\x01\xb0\xe0"	// adcs	r0, r0, r1, lsr #2
//#define ARM_CODE "\x32\x03\xa1\xe0"	// adc	r0, r1, r2, lsr r3
//#define ARM_CODE "\x22\x01\xa1\xe0"	// adc	r0, r1, r2, lsr #2
//#define ARM_CODE "\x65\x61\x4f\x50"	// subpl	r6, pc, r5, ror #2
//#define ARM_CODE "\x30\x30\x53\xe5"	// ldrb	r3, [r3, #-0x30]
//#define ARM_CODE "\xb6\x10\xdf\xe1"	// ldrh	r1, [pc, #0x6]
//#define ARM_CODE "\x02\x00\x9f\xef"	// svc #0x9f0002
//#define ARM_CODE "\x00\xc0\x27\xea"	// b 0x9F0002: FIXME: disasm as "b	#0x9f0000"
//#define ARM_CODE "\x12\x13\xa0\xe1"	// lsl r1, r2, r3
//#define ARM_CODE "\x82\x11\xa0\xe1"	// lsl	r1, r2, #0x3
//#define ARM_CODE "\x00\xc0\xa0\xe1"	// mov ip, r0
//#define ARM_CODE "\x02\x00\x12\xe3"	// tst r2, #2
//#define ARM_CODE "\x51\x12\xa0\xe1"	// asr r1, r2
//#define ARM_CODE "\x72\x10\xef\xe6"	// uxtb r1, r2
//#define ARM_CODE "\xe0\x0a\xb7\xee"	// vcvt.f64.f32	d0, s1
//#define ARM_CODE "\x9f\x0f\x91\xe1"	// ldrex	r0, [r1]
//#define ARM_CODE "\x0f\x06\x20\xf4"	// vld1.8	{d0, d1, d2}, [r0]
//#define ARM_CODE "\x72\x00\xa1\xe6"	// sxtab r0, r1, r2
//#define ARM_CODE "\x50\x06\x84\xf2"	// vmov.i32	q0, #0x40000000
//#define ARM_CODE "\x73\xe0\xb8\xee"	// mrc	p0, #5, lr, c8, c3, #3
//#define ARM_CODE "\x12\x02\x81\xe6"	// pkhbt	r0, r1, r2, lsl #0x4
//#define ARM_CODE "\x12\x00\xa0\xe6"	// ssat	r0, #0x1, r2
//#define ARM_CODE "\x03\x60\x2d\xe9"	// push	{r0, r1, sp, lr}
//#define ARM_CODE "\x8f\x40\x60\xf4"	// vld4.32	{d20, d21, d22, d23}, [r0]
//#define ARM_CODE "\xd0\x00\xc2\xe1"	// ldrd	r0, r1, [r2]
//#define ARM_CODE "\x08\xf0\xd0\xf5"	// pld	[r0, #0x8]
//#define ARM_CODE "\x10\x8b\xbc\xec"	// ldc	p11, c8, [r12], #64
//#define ARM_CODE "\xd4\x30\xd2\xe1"	// ldrsb	r3, [r2, #0x4] 
//#define ARM_CODE "\x11\x0f\xbe\xf2"	// vcvt.s32.f32	d0, d1, #2
//#define ARM_CODE "\x01\x01\x70\xe1"	// cmn	r0, r1, lsl #2
//#define ARM_CODE "\x06\x00\x91\xe2"	// adds	r0, r1, #6
//#define ARM_CODE "\x5b\xf0\x7f\xf5"	// dmb	ish
//#define ARM_CODE "\xf7\xff\xff\xfe"
//#define ARM_CODE "\x00\x20\xbd\xe8" // ldm	sp!, {sp}
//#define ARM_CODE "\x00\xa0\xbd\xe8"	// pop {sp, pc}
//#define ARM_CODE "\x90\x04\x0E\x00"	// muleq	lr, r0, r4
//#define ARM_CODE "\x90\x24\x0E\x00"	// muleq	lr, r0, r4
//#define ARM_CODE "\xb6\x10\x5f\xe1"	// ldrh	r1, [pc, #-6]

#define ARM_CODE "\x86\x48\x60\xf4\x4d\x0f\xe2\xf4\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"

//#define ARM_CODE "\x86\x48\x60\xf4"

//#define ARM_CODE2 "\xf0\x24"
//#define ARM_CODE2 "\x83\xb0"
#define ARM_CODE2 "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
//#define THUMB_CODE "\x70\x47"	// bl 0x26
//#define THUMB_CODE "\x07\xdd"	// ble 0x1c
//#define THUMB_CODE "\x00\x47"	// bx r0
//#define THUMB_CODE "\x01\x47"	// bx r0
//#define THUMB_CODE "\x02\x47"	// bx r0
//#define THUMB_CODE "\x0a\xbf" // itet eq

#define THUMB_CODE "\x60\xf9\x1f\x04\xe0\xf9\x4f\x07\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84\x52\xf8\x23\xf0"
//#define THUMB_CODE "\xe0\xf9\x4f\x07"

#define THUMB_CODE2 "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0\x18\xbf\xad\xbf\xf3\xff\x0b\x0c\x86\xf3\x00\x89\x80\xf3\x00\x8c\x4f\xfa\x99\xf6\xd0\xff\xa2\x01"
#define THUMB_MCLASS "\xef\xf3\x02\x80"
#define ARMV8 "\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5"

	struct platform platforms[] = {
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char *)ARM_CODE,
			sizeof(ARM_CODE) - 1,
			"ARM"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE,
			sizeof(THUMB_CODE) - 1,
			"Thumb"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)ARM_CODE2,
			sizeof(ARM_CODE2) - 1,
			"Thumb-mixed"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE2,
			sizeof(THUMB_CODE2) - 1,
			"Thumb-2 & register named with numbers",
			CS_OPT_SYNTAX_NOREGNAME
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
			(unsigned char*)THUMB_MCLASS,
			sizeof(THUMB_MCLASS) - 1,
			"Thumb-MClass"
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_ARM + CS_MODE_V8),
			(unsigned char*)ARMV8,
			sizeof(ARMV8) - 1,
			"Arm-V8"
		},
	};

	uint64_t address = 0x80001000;
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

		if (platforms[i].syntax)
			cs_option(handle, CS_OPT_SYNTAX, platforms[i].syntax);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(handle, &insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
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

