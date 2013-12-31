/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <capstone.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
};

static void print_string_hex(char *comment, unsigned char *str, int len)
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
	cs_arm *arm = &(ins->detail->arm);

	if (arm->op_count)
		printf("\top_count: %u\n", arm->op_count);

	int i;
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case ARM_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case ARM_OP_FP:
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
				break;
			case ARM_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case ARM_OP_PIMM:
				printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_CIMM:
				printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
				break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				// shift with constant value
				printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			else
				// shift with register
				printf("\t\t\tShift: %u = %s\n", op->shift.type,
						cs_reg_name(handle, op->shift.value));
		}
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		printf("\tCode condition: %u\n", ins->detail->arm.cc);

	if (arm->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm->writeback)
		printf("\tWrite-back: True\n");

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
#define ARM_CODE "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
//#define ARM_CODE2 "\xf0\x24"
//#define ARM_CODE2 "\x83\xb0"
#define ARM_CODE2 "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
//#define THUMB_CODE "\x70\x47"	// bl 0x26
//#define THUMB_CODE "\x07\xdd"	// ble 0x1c
//#define THUMB_CODE "\x00\x47"	// bx r0
//#define THUMB_CODE "\x01\x47"	// bx r0
//#define THUMB_CODE "\x02\x47"	// bx r0
//#define THUMB_CODE "\x0a\xbf" // itet eq
#define THUMB_CODE "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1"
#define THUMB_CODE2 "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"

	struct platform platforms[] = {
		{
			.arch = CS_ARCH_ARM,
			.mode = CS_MODE_ARM,
			.code = (unsigned char *)ARM_CODE,
			.size = sizeof(ARM_CODE) - 1,
			.comment = "ARM"
		},
		{
			.arch = CS_ARCH_ARM,
			.mode = CS_MODE_THUMB,
			.code = (unsigned char *)THUMB_CODE,
			.size = sizeof(THUMB_CODE) - 1,
			.comment = "Thumb"
		},
		{
			.arch = CS_ARCH_ARM,
			.mode = CS_MODE_THUMB,
			.code = (unsigned char *)ARM_CODE2,
			.size = sizeof(ARM_CODE2) - 1,
			.comment = "Thumb-mixed"
		},
		{
			.arch = CS_ARCH_ARM,
			.mode = CS_MODE_THUMB,
			.code = (unsigned char *)THUMB_CODE2,
			.size = sizeof(THUMB_CODE2) - 1,
			.comment = "Thumb-2"
		},
	};

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		if (cs_open(platforms[i].arch, platforms[i].mode, &handle))
			return;

		size_t count = cs_disasm_ex(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			size_t j;
			for (j = 0; j < count; j++) {
				printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%"PRIx64":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm_ex()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		cs_close(handle);
	}
}

int main()
{
	test();

	return 0;
}

