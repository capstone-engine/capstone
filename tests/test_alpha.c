/* Capstone Disassembler Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

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
	cs_alpha *alpha;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	alpha = &(ins->detail->alpha);
	if (alpha->op_count)
		printf("\top_count: %u\n", alpha->op_count);

	for (i = 0; i < alpha->op_count; i++) {
		cs_alpha_op *op = &(alpha->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ALPHA_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case ALPHA_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       op->imm);
			break;
		}
	}

	printf("\n");
}

static void test()
{
#define ALPHA_CODE \
	"\x02\x00\xbb\x27\x50\x7a\xbd\x23\xd0\xff\xde\x23\x00\x00\x5e\xb7"
#define ALPHA_CODE_BE \
	"\x27\xbb\x00\x02\x23\xbd\x7a\x50\x23\xde\xff\xd0\xb7\x5e\x00\x00"

	struct platform platforms[] = {
		{
			CS_ARCH_ALPHA,
			CS_MODE_LITTLE_ENDIAN,
			(unsigned char *)ALPHA_CODE,
			sizeof(ALPHA_CODE) - 1,
			"Alpha (Little-endian)",
		},
		{
			CS_ARCH_ALPHA,
			CS_MODE_BIG_ENDIAN,
			(unsigned char *)ALPHA_CODE_BE,
			sizeof(ALPHA_CODE) - 1,
			"Alpha (Big-endian)",
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
