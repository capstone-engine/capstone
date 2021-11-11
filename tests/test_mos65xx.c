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
			return "implied";
		case MOS65XX_AM_ACC:
			return "accumulator";
		case MOS65XX_AM_IMM:
			return "immediate value";
		case MOS65XX_AM_REL:
			return "relative";
		case MOS65XX_AM_INT:
			return "interrupt signature";
		case MOS65XX_AM_BLOCK:
			return "block move";
		case MOS65XX_AM_ZP:
			return "zero page";
		case MOS65XX_AM_ZP_X:
			return "zero page indexed with x";
		case MOS65XX_AM_ZP_Y:
			return "zero page indexed with y";
		case MOS65XX_AM_ZP_REL:
			return "relative bit branch";
		case MOS65XX_AM_ZP_IND:
			return "zero page indirect";
		case MOS65XX_AM_ZP_X_IND:
			return "zero page indexed with x indirect";
		case MOS65XX_AM_ZP_IND_Y:
			return "zero page indirect indexed with y";
		case MOS65XX_AM_ZP_IND_LONG:
			return "zero page indirect long";
		case MOS65XX_AM_ZP_IND_LONG_Y:
			return "zero page indirect long indexed with y";
		case MOS65XX_AM_ABS:
			return "absolute";
		case MOS65XX_AM_ABS_X:
			return "absolute indexed with x";
		case MOS65XX_AM_ABS_Y:
			return "absolute indexed with y";
		case MOS65XX_AM_ABS_IND:
			return "absolute indirect";
		case MOS65XX_AM_ABS_X_IND:
			return "absolute indexed with x indirect";
		case MOS65XX_AM_ABS_IND_LONG:
			return "absolute indirect long";
		case MOS65XX_AM_ABS_LONG:
			return "absolute long";
		case MOS65XX_AM_ABS_LONG_X:
			return "absolute long indexed with x";
		case MOS65XX_AM_SR:
			return "stack relative";
		case MOS65XX_AM_SR_IND_Y:
			return "stack relative indirect indexed with y";
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
#define M6502_CODE "\xa1\x12\xa5\x12\xa9\x12\xad\x34\x12\xb1\x12\xb5\x12\xb9\x34\x12\xbd\x34\x12" \
	"\x0d\x34\x12\x00\x81\x87\x6c\x01\x00\x85\xFF\x10\x00\x19\x42\x42\x00\x49\x42"

#define M65C02_CODE "\x1a\x3a" \
	"\x02\x12\x03\x5c\x34\x12"

#define MW65C02_CODE \
	"\x07\x12\x27\x12\x47\x12\x67\x12\x87\x12\xa7\x12\xc7\x12\xe7\x12" \
	"\x10\xfe\x0f\x12\xfd\x4f\x12\xfd\x8f\x12\xfd\xcf\x12\xfd"

#define M65816_CODE \
	"\xa9\x34\x12" "\xad\x34\x12" "\xbd\x34\x12" "\xb9\x34\x12" \
	"\xaf\x56\x34\x12" "\xbf\x56\x34\x12" \
	"\xa5\x12" "\xb5\x12" "\xb2\x12" "\xa1\x12" "\xb1\x12" "\xa7\x12" "\xb7\x12" \
	"\xa3\x12" "\xb3\x12" \
	"\xc2\x00" "\xe2\x00" "\x54\x34\x12" "\x44\x34\x12" "\x02\x12"

	struct platform platforms[] = {
		{
			CS_ARCH_MOS65XX,
			(cs_mode)(CS_MODE_MOS65XX_6502),
			(unsigned char *)M6502_CODE,
			sizeof(M6502_CODE) - 1,
			"MOS65XX_6502"
		},
		{
			CS_ARCH_MOS65XX,
			(cs_mode)(CS_MODE_MOS65XX_65C02),
			(unsigned char *)M65C02_CODE,
			sizeof(M65C02_CODE) - 1,
			"MOS65XX_65C02"
		},
		{
			CS_ARCH_MOS65XX,
			(cs_mode)(CS_MODE_MOS65XX_W65C02),
			(unsigned char *)MW65C02_CODE,
			sizeof(MW65C02_CODE) - 1,
			"MOS65XX_W65C02"
		},
		{
			CS_ARCH_MOS65XX,
			(cs_mode)(CS_MODE_MOS65XX_65816_LONG_MX),
			(unsigned char *)M65816_CODE,
			sizeof(M65816_CODE) - 1,
			"MOS65XX_65816 (long m/x)"
		},
	};

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u (%s)\n", err, cs_strerror(err));
			abort();
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MOTOROLA);

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
