/* Capstone Disassembler Engine */
/* SuperH Backend by Yoshinori Sato <ysato@users.sourceforge.jp> */

#include <stdio.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#define WITH_DETAILS

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
};

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);

	for (c = str; c < str + len; c++)
		printf("0x%02x ", *c & 0xff);

	printf("\n");
}

static void print_string_hex_short(unsigned char *str, size_t len)
{
	unsigned char *c;

	for (c = str; c < str + len; c++)
		printf("%02x", *c & 0xff);
}

static void print_read_write_regs(csh handle, cs_detail *detail)
{
	int i;

	if (detail->regs_read_count > 0) {
		printf("\tRegisters read:");

		for (i = 0; i < detail->regs_read_count; ++i)
			printf(" %s",
				cs_reg_name(handle, detail->regs_read[i]));

		printf("\n");
	}

	if (detail->regs_write_count > 0) {
		printf("\tRegisters modified:");

		for (i = 0; i < detail->regs_write_count; ++i)
			printf(" %s",
				cs_reg_name(handle, detail->regs_write[i]));

		printf("\n");
	}
}

static char *reg_address_msg[] = {
	"Register indirect",
	"Register indirect with predecrement",
	"Register indirect with postincrement",
};

static void print_insn_detail(csh handle, cs_insn *insn)
{
	cs_detail *detail = insn->detail;
	cs_sh *sh = NULL;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (detail == NULL)
		return;

	sh = &detail->sh;

	if (sh->op_count)
		printf("\top_count: %u\n", sh->op_count);

	for (i = 0; i < sh->op_count; i++) {
		cs_sh_op *op = &(sh->operands[i]);

		switch ((int)op->type) {
		default:
			break;

		case SH_OP_REG:
			printf("\t\toperands[%u].type: REGISTER = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;

		case SH_OP_IMM:
			printf("\t\toperands[%u].type: IMMEDIATE = #%llu\n", i,
			       op->imm);
			break;

		case SH_OP_MEM:
			printf("\t\toperands[%u].type: MEM ", i);
			switch(op->mem.address) {
			case SH_OP_MEM_REG_IND:
			case SH_OP_MEM_REG_POST:
			case SH_OP_MEM_REG_PRE:
				printf("%s REG %s\n",
				       reg_address_msg[op->mem.address - SH_OP_MEM_REG_IND],
				       cs_reg_name(handle, op->mem.reg));
				break;
			case SH_OP_MEM_REG_DISP:
				printf("Register indirect with displacement REG %s, DISP %d\n",
				       cs_reg_name(handle, op->mem.reg),
				       op->mem.disp);
				break;
				
			case SH_OP_MEM_REG_R0:
				printf("R0 indexed\n");
				break;
				
			case SH_OP_MEM_GBR_DISP:
				printf("GBR base with displacement DISP %d\n",
				       op->mem.disp);
				break;
				
			case SH_OP_MEM_GBR_R0:
				printf("GBR base with R0 indexed\n");
				break;

			case SH_OP_MEM_PCR:
				printf("PC relative Address=0x%08x\n",
				       op->mem.disp);
				break;

			case SH_OP_MEM_TBR_DISP:
				printf("TBR base with displacement DISP %d\n",
				       op->mem.disp);
				break;
			case SH_OP_MEM_INVALID:
				break;
			}
			break;
		}

		if (sh->size != 0)
			printf("\t\t\tsize: %u\n", sh->size);

	}

	print_read_write_regs(handle, detail);

	if (detail->groups_count) {
		printf("\tgroups_count: %u\n", detail->groups_count);
	}

	printf("\n");
}

static bool consistency_checks()
{
	return true;
}

static void test()
{
#define SH4A_CODE \
  "\xc\x31\x10\x20\x22\x21\x36\x64\x46\x25\x12\x12\x1c\x2\x8\xc1\x5\xc7\xc" \
  "\x71\x1f\x2\x22\xcf\x6\x89\x23\x0\x2b\x41\xb\x0\xe\x40\x32\x0\xa\xf1\x9\x0"

#define SH2A_CODE \
  "\x32\x11\x92\x0\x32\x49\x31\x0"

	struct platform platforms[] = {
		{
			CS_ARCH_SH,
			(cs_mode)(CS_MODE_SH4A | CS_MODE_SHFPU),
			(unsigned char *)SH4A_CODE,
			sizeof(SH4A_CODE) - 1,
			"SH_SH4A",
		},
		{
			CS_ARCH_SH,
			(cs_mode)(CS_MODE_SH2A | CS_MODE_SHFPU | CS_MODE_BIG_ENDIAN),
			(unsigned char *)SH2A_CODE,
			sizeof(SH2A_CODE) - 1,
			"SH_SH2A",
		},
	};

	uint64_t address = 0x80000000;
	csh handle;
	cs_insn *insn;
	int i;
	size_t count;
	const char *nine_spaces = "         ";

	if (!consistency_checks())
		abort();

	for (i = 0; i < sizeof(platforms) / sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode,
				&handle);

		if (err) {
			printf("Failed on cs_open() with error returned: %u\n",
				err);
			abort();
		}

#ifdef WITH_DETAILS
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
#endif

		count = cs_disasm(handle, platforms[i].code, platforms[i].size,
				address, 0, &insn);

		if (count) {
			size_t j;

			printf("********************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code: ", platforms[i].code,
				platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				int slen;
				printf("0x%08x: ", (uint32_t)insn[j].address);
				print_string_hex_short(insn[j].bytes,
					insn[j].size);
				printf("%.*s", 1 + ((5 - insn[j].size) * 2),
					nine_spaces);
				printf("%s", insn[j].mnemonic);
				slen = (int)strlen(insn[j].mnemonic);
				printf("%.*s", 1 + (5 - slen), nine_spaces);
				printf("%s\n", insn[j].op_str);
#ifdef WITH_DETAILS
				print_insn_detail(handle, &insn[j]);
#endif
			}

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		}
		else {
			printf("********************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code,
				platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			abort();
		}

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}
