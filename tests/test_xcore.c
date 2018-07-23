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
	const char *comment;
};

static csh handle;

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
	cs_xcore *xcore;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	xcore = &(ins->detail->xcore);
	if (xcore->op_count)
		printf("\top_count: %u\n", xcore->op_count);

	for (i = 0; i < xcore->op_count; i++) {
		cs_xcore_op *op = &(xcore->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case XCORE_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case XCORE_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case XCORE_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != XCORE_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != XCORE_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
				if (op->mem.direct != 1)
					printf("\t\t\toperands[%u].mem.direct: -1\n", i);


				break;
		}
	}

	printf("\n");
}

static void test()
{
#define XCORE_CODE "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10\x09\xfd\xec\xa7"

	struct platform platforms[] = {
		{
			CS_ARCH_XCORE,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)XCORE_CODE,
			sizeof(XCORE_CODE) - 1,
			"XCore",
		},
	};

	uint64_t address = 0x1000;
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
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
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
