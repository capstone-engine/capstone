/* Capstone Disassembler Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

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
	cs_arc *arc;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arc = &(ins->detail->arc);
	if (arc->op_count)
		printf("\top_count: %u\n", arc->op_count);

	for (i = 0; i < arc->op_count; i++) {
		cs_arc_op *op = &(arc->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ARC_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case ARC_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n",
			       i, op->imm);
			break;
		}
	}

	printf("\n");
}

static void test()
{
#define ARC_CODE "\x04\x11\x00\x00\x04\x11\x00\x02\x04\x11\x00\x04\x04\x11\x00\x01\x04\x11\x00\x03\x04\x11\x00\x05\x04\x11\x80\x00\x04\x11\x80\x02\x04\x11\x80\x04"

	struct platform platforms[] = {
		{
			CS_ARCH_ARC,
			CS_MODE_LITTLE_ENDIAN,
			(unsigned char *)ARC_CODE,
			sizeof(ARC_CODE) - 1,
			"ARC",
		}
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
			print_string_hex("Code: ", platforms[i].code,
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
