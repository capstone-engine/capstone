/* Second-Best Disassembler Engine */
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
	cs_opt_type opt_type;
	cs_opt_value opt_value;
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

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
	int i;
	cs_x86 *x86 = &(ins->x86);

	print_string_hex("\tPrefix:", x86->prefix, 5);

	if (x86->segment != X86_REG_INVALID)
		printf("\tSegment override: %s\n", cs_reg_name(handle, x86->segment));

	print_string_hex("\tOpcode:", x86->opcode, 3);
	printf("\top_size: %u, addr_size: %u, disp_size: %u, imm_size: %u\n", x86->op_size, x86->addr_size, x86->disp_size, x86->imm_size);
	printf("\tmodrm: 0x%x\n", x86->modrm);
	printf("\tdisp: 0x%x\n", x86->disp);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		printf("\tsib: 0x%x\n", x86->sib);
		if (x86->sib_index != X86_REG_INVALID)
			printf("\tsib_index: %s, sib_scale: %u, sib_base: %s\n",
					cs_reg_name(handle, x86->sib_index),
					x86->sib_scale,
					cs_reg_name(handle, x86->sib_base));
	}

	int count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		printf("\timm_count: %u\n", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			printf("\t\timms[%u]: 0x%"PRIx64 "\n", i, x86->operands[index].imm);
		}
	}

	if (x86->op_count)
		printf("\top_count: %u\n", x86->op_count);
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%"PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_FP:
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != 0)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != 0)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				break;
			default:
				break;
		}
	}

	printf("\n");
}

static void test()
{
//#define X86_CODE32 "\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x78\x56\x00\x00"
//#define X86_CODE32 "\x05\x78\x56\x00\x00"
//#define X86_CODE32 "\x01\xd8"
//#define X86_CODE32 "\x05\x23\x01\x00\x00"
//#define X86_CODE32 "\x8d\x87\x89\x67\x00\x00"
//#define X86_CODE32 "\xa1\x13\x48\x6d\x3a\x8b\x81\x23\x01\x00\x00\x8b\x84\x39\x23\x01\x00\x00"
//#define X86_CODE32 "\xb4\xc6"	// mov	ah, 0x6c
//#define X86_CODE32 "\x77\x04"	// ja +6
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
//#define X86_CODE64 "\xe9\x79\xff\xff\xff"	// jmp 0xf7e

#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
//#define X86_CODE16 "\x67\x00\x18"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
//#define X86_CODE32 "\x0f\xa7\xc0"	// xstorerng
//#define X86_CODE32 "\x64\xa1\x18\x00\x00\x00"	// mov eax, dword ptr fs:[18]
//#define X86_CODE32 "\x64\xa3\x00\x00\x00\x00"	// mov [fs:0x0], eax
//#define X86_CODE32 "\xd1\xe1"	// shl ecx, 1
//#define X86_CODE32 "\xd1\xc8"	// ror eax, 1
//#define X86_CODE32 "\x83\xC0\x80"	// add	eax, -x80
//#define X86_CODE32 "\xe8\x26\xfe\xff\xff"		// call	0xe2b
//#define X86_CODE32 "\xcd\x80"		// int 0x80
//#define X86_CODE32 "\x24\xb8"		// and    $0xb8,%al
//#define X86_CODE32 "\xf0\x01\xd8"   // lock add eax,ebx
//#define X86_CODE32 "\xf3\xaa"		// rep stosb

	struct platform platforms[] = {
		{
			.arch = CS_ARCH_X86,
			.mode = CS_MODE_16,
			.code = (unsigned char *)X86_CODE16,
			.size = sizeof(X86_CODE16) - 1,
			.comment = "X86 16bit (Intel syntax)"
		},
		{
			.arch = CS_ARCH_X86,
			.mode = CS_MODE_32,
			.code = (unsigned char *)X86_CODE32,
			.size = sizeof(X86_CODE32) - 1,
			.comment = "X86 32 (AT&T syntax)",
			.opt_type = CS_OPT_SYNTAX,
			.opt_value = CS_OPT_SYNTAX_ATT,
		},
		{
			.arch = CS_ARCH_X86,
			.mode = CS_MODE_32,
			.code = (unsigned char *)X86_CODE32,
			.size = sizeof(X86_CODE32) - 1,
			.comment = "X86 32 (Intel syntax)"
		},
		{
			.arch = CS_ARCH_X86,
			.mode = CS_MODE_64,
			.code = (unsigned char *)X86_CODE64,
			.size = sizeof(X86_CODE64) - 1,
			.comment = "X86 64 (Intel syntax)"
		},
	};

	uint64_t address = 0x1000;
	//cs_insn insn[16];
	cs_insn *insn;
	int i;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		if (cs_open(platforms[i].arch, platforms[i].mode, &handle))
			return;

		if (platforms[i].opt_type)
			cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

		//size_t count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, insn);
		size_t count = cs_disasm_dyn(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			size_t j;
			for (j = 0; j < count; j++) {
				printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(handle, platforms[i].mode, &insn[j]);
			}
			printf("0x%"PRIx64":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm_dyn()
			cs_free(insn);
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
