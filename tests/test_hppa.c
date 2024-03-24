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
	cs_hppa *hppa;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	hppa = &(ins->detail->hppa);
	if (hppa->op_count)
		printf("\top_count: %u\n", hppa->op_count);

	for (i = 0; i < hppa->op_count; i++) {
		cs_hppa_op *op = &(hppa->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case HPPA_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case HPPA_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n",
			       i, op->imm);
			break;
		case HPPA_OP_IDX_REG:
			printf("\t\toperands[%u].type: IDX_REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case HPPA_OP_DISP:
			printf("\t\toperands[%u].type: DISP = 0x%" PRIx64 "\n",
			       i, op->imm);
			break;
		case HPPA_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.space != HPPA_OP_INVALID) {
				printf("\t\t\toperands[%u].mem.space: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.space));
			}
			printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
			       cs_reg_name(handle, op->mem.base));
			break;
		case HPPA_OP_TARGET:
			printf("\t\toperands[%u].type: ", i);
			if (op->imm >= 0x8000000000000000)
				printf("TARGET = -0x%" PRIx64 "\n", -op->imm);
			else
				printf("TARGET = 0x%" PRIx64 "\n", op->imm);
			break;
		}
	}

	printf("\n");
}

static void test()
{
#define HPPA_20_CODE_BE \
	"\x00\x20\x50\xa2\x00\x01\x58\x20\x00\x00\x44\xa1\x00\x41\x18\x40\x00\x20\x08\xa2\x01\x60\x48\xa1\x01\x61\x18\xc0\x00\x00\x14\xa1\x00\x0f\x0d\x61\x00\x0f\x0e\x61\x00\x01\x18\x60\x00\x00\x0c\x00\x00\x00\x0c\xa0\x03\xff\xc0\x1f\x00\x00\x04\x00\x00\x10\x04\x00\x04\x22\x51\x83\x04\x22\x51\xc3\x04\x22\x51\x83\x04\x2f\x71\x83\x04\x2f\x71\xc3\x04\x2f\x71\x83\x04\x41\x53\x43\x04\x41\x53\x63\x04\x41\x53\x03\x04\x41\x12\x00\x04\x41\x16\x00\x04\x41\x16\x20\x04\x41\x42\x00\x04\x41\x46\x00\x04\x41\x46\x20\x04\x41\x12\x40\x04\x41\x12\x60\x04\x41\x42\x40\x04\x41\x42\x60\x04\x41\x18\x00\x04\x41\x08\x00\x04\x41\x13\x80\x04\x41\x13\xa0\x04\x41\x52\x80\x04\x41\x52\xa0\x04\x5e\x72\x80\x04\x41\x42\x80\x04\x41\x52\xc0\x04\x41\x52\xe0\x04\x41\x42\xc0\x04\x41\x42\xe0\x14\x00\xde\xad"
#define HPPA_20_CODE \
	"\xa2\x50\x20\x00\x20\x58\x01\x00\xa1\x44\x00\x00\x40\x18\x41\x00\xa2\x08\x20\x00\xa1\x48\x60\x01\xc0\x18\x61\x01\xa1\x14\x00\x00\x61\x0d\x0f\x00\x61\x0e\x0f\x00\x60\x18\x01\x00\x00\x0c\x00\x00\xa0\x0c\x00\x00\x1f\xc0\xff\x03\x00\x04\x00\x00\x00\x04\x10\x00\x83\x51\x22\x04\xc3\x51\x22\x04\x83\x51\x22\x04\x83\x71\x2f\x04\xc3\x71\x2f\x04\x83\x71\x2f\x04\x43\x53\x41\x04\x63\x53\x41\x04\x03\x53\x41\x04\x00\x12\x41\x04\x00\x16\x41\x04\x20\x16\x41\x04\x00\x42\x41\x04\x00\x46\x41\x04\x20\x46\x41\x04\x40\x12\x41\x04\x60\x12\x41\x04\x40\x42\x41\x04\x60\x42\x41\x04\x00\x18\x41\x04\x00\x08\x41\x04\x80\x13\x41\x04\xa0\x13\x41\x04\x80\x52\x41\x04\xa0\x52\x41\x04\x80\x72\x5e\x04\x80\x42\x41\x04\xc0\x52\x41\x04\xe0\x52\x41\x04\xc0\x42\x41\x04\xe0\x42\x41\x04\xad\xde\x00\x14"
#define HPPA_11_CODE_BE \
	"\x24\x41\x40\xc3\x24\x41\x60\xc3\x24\x41\x40\xe3\x24\x41\x60\xe3\x24\x41\x68\xe3\x2c\x41\x40\xc3\x2c\x41\x60\xc3\x2c\x41\x40\xe3\x2c\x41\x60\xe3\x2c\x41\x68\xe3\x24\x62\x42\xc1\x24\x62\x62\xc1\x24\x62\x42\xe1\x24\x62\x46\xe1\x24\x62\x62\xe1\x24\x62\x6a\xe1\x2c\x62\x42\xc1\x2c\x62\x62\xc1\x2c\x62\x42\xe1\x2c\x62\x46\xe1\x2c\x62\x62\xe1\x2c\x62\x6a\xe1\x24\x3e\x50\xc2\x24\x3e\x50\xe2\x24\x3e\x70\xe2\x24\x3e\x78\xe2\x2c\x3e\x50\xc2\x2c\x3e\x50\xe2\x2c\x3e\x70\xe2\x2c\x3e\x78\xe2\x24\x5e\x52\xc1\x24\x5e\x52\xe1\x24\x5e\x56\xe1\x24\x5e\x72\xe1\x24\x5e\x7a\xe1\x2c\x5e\x52\xc1\x2c\x5e\x52\xe1\x2c\x5e\x56\xe1\x2c\x5e\x72\xe1\x2c\x5e\x7a\xe1"
#define HPPA_11_CODE \
	"\xc3\x40\x41\x24\xc3\x60\x41\x24\xe3\x40\x41\x24\xe3\x60\x41\x24\xe3\x68\x41\x24\xc3\x40\x41\x2c\xc3\x60\x41\x2c\xe3\x40\x41\x2c\xe3\x60\x41\x2c\xe3\x68\x41\x2c\xc1\x42\x62\x24\xc1\x62\x62\x24\xe1\x42\x62\x24\xe1\x46\x62\x24\xe1\x62\x62\x24\xe1\x6a\x62\x24\xc1\x42\x62\x2c\xc1\x62\x62\x2c\xe1\x42\x62\x2c\xe1\x46\x62\x2c\xe1\x62\x62\x2c\xe1\x6a\x62\x2c\xc2\x50\x3e\x24\xe2\x50\x3e\x24\xe2\x70\x3e\x24\xe2\x78\x3e\x24\xc2\x50\x3e\x2c\xe2\x50\x3e\x2c\xe2\x70\x3e\x2c\xe2\x78\x3e\x2c\xc1\x52\x5e\x24\xe1\x52\x5e\x24\xe1\x56\x5e\x24\xe1\x72\x5e\x24\xe1\x7a\x5e\x24\xc1\x52\x5e\x2c\xe1\x52\x5e\x2c\xe1\x56\x5e\x2c\xe1\x72\x5e\x2c\xe1\x7a\x5e\x2c"

	struct platform platforms[] = {
		{
			CS_ARCH_HPPA,
			CS_MODE_BIG_ENDIAN | CS_MODE_HPPA_20,
			(unsigned char *)HPPA_20_CODE_BE,
			sizeof(HPPA_20_CODE_BE) - 1,
			"HPPA 2.0 (Big-endian)",
		},
		{
			CS_ARCH_HPPA,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_HPPA_20,
			(unsigned char *)HPPA_20_CODE,
			sizeof(HPPA_20_CODE) - 1,
			"HPPA 2.0 (Little-endian)",
		},
		{
			CS_ARCH_HPPA,
			CS_MODE_BIG_ENDIAN | CS_MODE_HPPA_11,
			(unsigned char *)HPPA_11_CODE_BE,
			sizeof(HPPA_11_CODE_BE) - 1,
			"HPPA 1.1 (Big-endian)",
		},
		{
			CS_ARCH_HPPA,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_HPPA_11,
			(unsigned char *)HPPA_11_CODE,
			sizeof(HPPA_11_CODE) - 1,
			"HPPA 1.1 (Little-endian)",
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