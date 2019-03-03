/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char* code;
	size_t size;
	const char* comment;
};

static csh handle;

static void print_string_hex(const char* comment, unsigned char* str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

const char* s_addressing_modes[] = {
	"<invalid mode>",

	"Register Direct - Data",
	"Register Direct - Address",

	"Register Indirect - Address",
	"Register Indirect - Address with Postincrement",
	"Register Indirect - Address with Predecrement",
	"Register Indirect - Address with Displacement",

	"Address Register Indirect With Index - 8-bit displacement",
	"Address Register Indirect With Index - Base displacement",

	"Memory indirect - Postindex",
	"Memory indirect - Preindex",

	"Program Counter Indirect - with Displacement",

	"Program Counter Indirect with Index - with 8-Bit Displacement",
	"Program Counter Indirect with Index - with Base Displacement",

	"Program Counter Memory Indirect - Postindexed",
	"Program Counter Memory Indirect - Preindexed",

	"Absolute Data Addressing  - Short",
	"Absolute Data Addressing  - Long",
	"Immediate value",
};

static void print_read_write_regs(cs_detail* detail)
{
	int i;

	for (i = 0; i < detail->regs_read_count; ++i)
	{
		uint16_t reg_id = detail->regs_read[i];
		const char* reg_name = cs_reg_name(handle, reg_id);
		printf("\treading from reg: %s\n", reg_name);
	}

	for (i = 0; i < detail->regs_write_count; ++i)
	{
		uint16_t reg_id = detail->regs_write[i];
		const char* reg_name = cs_reg_name(handle, reg_id);
		printf("\twriting to reg:   %s\n", reg_name);
	}
}

static void print_insn_detail(cs_insn *ins)
{
	cs_m68k* m68k;
	cs_detail* detail;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	detail = ins->detail;
	m68k = &detail->m68k;
	if (m68k->op_count)
		printf("\top_count: %u\n", m68k->op_count);

	print_read_write_regs(detail);

	printf("\tgroups_count: %u\n", detail->groups_count);

	for (i = 0; i < m68k->op_count; i++) {
		cs_m68k_op* op = &(m68k->operands[i]);

		switch((int)op->type) {
			default:
				break;
			case M68K_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case M68K_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, (int)op->imm);
				break;
			case M68K_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base_reg != M68K_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base_reg));
				if (op->mem.index_reg != M68K_REG_INVALID) {
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index_reg));
					printf("\t\t\toperands[%u].mem.index: size = %c\n",
							i, op->mem.index_size ? 'l' : 'w');
				}
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
				if (op->mem.scale != 0)
					printf("\t\t\toperands[%u].mem.scale: %d\n", i, op->mem.scale);

				printf("\t\taddress mode: %s\n", s_addressing_modes[op->address_mode]);
				break;
			case M68K_OP_FP_SINGLE:
				printf("\t\toperands[%u].type: FP_SINGLE\n", i);
				printf("\t\t\toperands[%u].simm: %f\n", i, op->simm);
				break;
			case M68K_OP_FP_DOUBLE:
				printf("\t\toperands[%u].type: FP_DOUBLE\n", i);
				printf("\t\t\toperands[%u].dimm: %lf\n", i, op->dimm);
				break;
			case M68K_OP_REG_BITS:
				printf("\t\toperands[%u].type: REG_BITS = $%x\n", i, op->register_bits);
				break;
			case M68K_OP_REG_PAIR:
				printf("\t\toperands[%u].type: REG_PAIR = (%s, %s)\n", i,
					cs_reg_name(handle, op->reg_pair.reg_0),
					cs_reg_name(handle, op->reg_pair.reg_1));
				break;
		}
	}

	printf("\n");
}

static void test()
{
#define M68K_CODE "\x4C\x00\x54\x04\x48\xe7\xe0\x30\x4C\xDF\x0C\x07\xd4\x40\x87\x5a\x4e\x71\x02\xb4\xc0\xde\xc0\xde\x5c\x00\x1d\x80\x71\x12\x01\x23\xf2\x3c\x44\x22\x40\x49\x0e\x56\x54\xc5\xf2\x3c\x44\x00\x44\x7a\x00\x00\xf2\x00\x0a\x28\x4E\xB9\x00\x00\x00\x12\x4E\x75"
	struct platform platforms[] = {
		{
			CS_ARCH_M68K,
			(cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040),
			(unsigned char*)M68K_CODE,
			sizeof(M68K_CODE) - 1,
			"M68K",
		},
	};

	uint64_t address = 0x01000;
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
			print_string_hex("Code: ", platforms[i].code, platforms[i].size);
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
