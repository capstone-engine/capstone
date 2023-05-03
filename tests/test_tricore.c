/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
};

static csh handle;

static void print_string_hex(char *comment, unsigned char *str, size_t len)
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
	cs_tricore *tricore;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	tricore = &(ins->detail->tricore);
	if (tricore->op_count)
		printf("\top_count: %u\n", tricore->op_count);

	for (i = 0; i < tricore->op_count; i++) {
		cs_tricore_op *op = &(tricore->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case TRICORE_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case TRICORE_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       op->imm);
			break;
		case TRICORE_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != TRICORE_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.base));
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i,
				       op->mem.disp);

			break;
		}
	}

	printf("\n");
}

static void test()
{
//#define TRICORE_CODE "\x16\x01\x20\x01\x1d\x00\x02\x00\x8f\x70\x00\x11\x40\xae\x89\xee\x04\x09\x42\xf2\xe2\xf2\xc2\x11\x19\xff\xc0\x70\x19\xff\x20\x10"
#define TRICORE_CODE \
	"\x09\xcf\xbc\xf5\x09\xf4\x01\x00\x89\xfb\x8f\x74\x89\xfe\x48\x01\x29\x00\x19\x25\x29\x03\x09\xf4\x85\xf9\x68\x0f\x16\x01"

	struct platform platforms[] = {
		{
			CS_ARCH_TRICORE,
			CS_MODE_TRICORE_162,
			(unsigned char *)TRICORE_CODE,
			sizeof(TRICORE_CODE) - 1,
			"TriCore",
		},
	};

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms) / sizeof(platforms[0]); i++) {
		cs_err err =
			cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n",
			       err);
			continue;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size,
				  address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code,
					 platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n",
				       insn[j].address, insn[j].mnemonic,
				       insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%" PRIx64 ":\n",
			       insn[j - 1].address + insn[j - 1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code,
					 platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
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
