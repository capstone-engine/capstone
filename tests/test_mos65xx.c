/* Capstone Disassembler Engine */
/* By Sebastian Macke <sebastian@macke.de>, 2018 */

#include <stdio.h>
#include <stdlib.h>

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
		printf(" 0x%02x", *c & 0xff);
	}

	printf("\n");
}

static const char *get_am_name(mos65xx_address_mode mode)
{
	switch(mode) {
		default:
		case MOS65XX_AM_NONE:
			return "No address mode";
		case MOS65XX_AM_IMP:
			return "implied addressing (no addressing mode)";
		case MOS65XX_AM_ACC:
			return "accumulator addressing";
		case MOS65XX_AM_ABS:
			return "absolute addressing";
		case MOS65XX_AM_ZP:
			return "zeropage addressing";
		case MOS65XX_AM_IMM:
			return "8 Bit immediate value";
		case MOS65XX_AM_ABSX:
			return "indexed absolute addressing by the X index register";
		case MOS65XX_AM_ABSY:
			return "indexed absolute addressing by the Y index register";
		case MOS65XX_AM_INDX:
			return "indexed indirect addressing by the X index register";
		case MOS65XX_AM_INDY:
			return "indirect indexed addressing by the Y index register";
		case MOS65XX_AM_ZPX:
			return "indexed zeropage addressing by the X index register";
		case MOS65XX_AM_ZPY:
			return "indexed zeropage addressing by the Y index register";
		case MOS65XX_AM_REL:
			return "relative addressing used by branches";
		case MOS65XX_AM_IND:
			return "absolute indirect addressing";
	}
}


static void print_insn_detail(cs_insn *ins)
{
	cs_mos65xx *mos65xx;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	mos65xx = &(ins->detail->mos65xx);

	// printf("insn_detail\n");
	printf("\taddress mode: %s\n", get_am_name(mos65xx->am));
	printf("\tmodifies flags: %s\n", mos65xx->modifies_flags ? "true": "false");

	if (mos65xx->op_count)
		printf("\top_count: %u\n", mos65xx->op_count);

	for (i = 0; i < mos65xx->op_count; i++) {
		cs_mos65xx_op *op = &(mos65xx->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case MOS65XX_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case MOS65XX_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case MOS65XX_OP_MEM:
				printf("\t\toperands[%u].type: MEM = 0x%x\n", i, op->mem);
				break;
		}
	}
}

static void test()
{
#define MOS65XX_CODE "\x0d\x34\x12\x00\x81\x87\x6c\x01\x00\x85\xFF\x10\x00\x19\x42\x42\x00\x49\x42"

	struct platform platforms[] = {
		{
			CS_ARCH_MOS65XX,
			0,
			(unsigned char *)MOS65XX_CODE,
			sizeof(MOS65XX_CODE) - 1,
			"MOS65XX"
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
				puts("");
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
