/* Capstone Disassembler Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

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

static const char *s_access[] = {
	"UNCHANGED", "READ", "WRITE", "READ | WRITE",
};

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

static void print_insn_detail(csh handle, cs_insn *insn)
{
	cs_detail *detail = insn->detail;
	cs_m680x *m680x = NULL;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (detail == NULL)
		return;

	m680x = &detail->m680x;

	if (m680x->op_count)
		printf("\top_count: %u\n", m680x->op_count);

	for (i = 0; i < m680x->op_count; i++) {
		cs_m680x_op *op = &(m680x->operands[i]);
		const char *comment;

		switch ((int)op->type) {
		default:
			break;

		case M680X_OP_REGISTER:
			comment = "";

			if ((i == 0 && (m680x->flags &
						M680X_FIRST_OP_IN_MNEM)) ||
				((i == 1 && (m680x->flags &
							M680X_SECOND_OP_IN_MNEM))))
				comment = " (in mnemonic)";

			printf("\t\toperands[%u].type: REGISTER = %s%s\n", i,
				cs_reg_name(handle, op->reg), comment);
			break;

		case M680X_OP_CONSTANT:
			printf("\t\toperands[%u].type: CONSTANT = %u\n", i,
				op->const_val);
			break;

		case M680X_OP_IMMEDIATE:
			printf("\t\toperands[%u].type: IMMEDIATE = #%d\n", i,
				op->imm);
			break;

		case M680X_OP_DIRECT:
			printf("\t\toperands[%u].type: DIRECT = 0x%02x\n", i,
				op->direct_addr);
			break;

		case M680X_OP_EXTENDED:
			printf("\t\toperands[%u].type: EXTENDED %s = 0x%04x\n",
				i, op->ext.indirect ? "INDIRECT" : "",
				op->ext.address);
			break;

		case M680X_OP_RELATIVE:
			printf("\t\toperands[%u].type: RELATIVE = 0x%04x\n", i,
				op->rel.address);
			break;

		case M680X_OP_INDEXED:
			printf("\t\toperands[%u].type: INDEXED%s\n", i,
				(op->idx.flags & M680X_IDX_INDIRECT) ?
				" INDIRECT" : "");

			if (op->idx.base_reg != M680X_REG_INVALID)
				printf("\t\t\tbase register: %s\n",
					cs_reg_name(handle, op->idx.base_reg));

			if (op->idx.offset_reg != M680X_REG_INVALID)
				printf("\t\t\toffset register: %s\n",
					cs_reg_name(handle, op->idx.offset_reg));

			if ((op->idx.offset_bits != 0) &&
				(op->idx.offset_reg == M680X_REG_INVALID) &&
				!op->idx.inc_dec) {
				printf("\t\t\toffset: %d\n", op->idx.offset);

				if (op->idx.base_reg == M680X_REG_PC)
					printf("\t\t\toffset address: 0x%x\n",
						op->idx.offset_addr);

				printf("\t\t\toffset bits: %u\n",
					op->idx.offset_bits);
			}

			if (op->idx.inc_dec) {
				const char *post_pre = op->idx.flags &
					M680X_IDX_POST_INC_DEC ? "post" : "pre";
				const char *inc_dec = (op->idx.inc_dec > 0) ?
					"increment" : "decrement";

				printf("\t\t\t%s %s: %d\n", post_pre, inc_dec,
					abs(op->idx.inc_dec));
			}

			break;
		}

		if (op->size != 0)
			printf("\t\t\tsize: %u\n", op->size);

		if (op->access != CS_AC_INVALID)
			printf("\t\t\taccess: %s\n", s_access[op->access]);

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
#define M6800_CODE \
  "\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39"

#define M6801_CODE \
  "\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39"

#define M6805_CODE \
  "\x04\x7f\x00\x17\x22\x28\x00\x2e\x00\x40\x42\x5a\x70\x8e\x97\x9c" \
  "\xa0\x15\xad\x00\xc3\x10\x00\xda\x12\x34\xe5\x7f\xfe"

#define M6808_CODE \
  "\x31\x22\x00\x35\x22\x45\x10\x00\x4b\x00\x51\x10\x52\x5e\x22\x62" \
  "\x65\x12\x34\x72\x84\x85\x86\x87\x8a\x8b\x8c\x94\x95\xa7\x10\xaf\x10" \
  "\x9e\x60\x7f\x9e\x6b\x7f\x00\x9e\xd6\x10\x00\x9e\xe6\x7f"

#define HCS08_CODE \
  "\x32\x10\x00\x9e\xae\x9e\xce\x7f\x9e\xbe\x10\x00\x9e\xfe\x7f" \
  "\x3e\x10\x00\x9e\xf3\x7f\x96\x10\x00\x9e\xff\x7f\x82"

#define M6811_CODE \
  "\x02\x03\x12\x7f\x10\x00\x13\x99\x08\x00\x14\x7f\x02\x15\x7f\x01" \
  "\x1e\x7f\x20\x00\x8f\xcf" \
  "\x18\x08\x18\x30\x18\x3c\x18\x67\x18\x8c\x10\x00\x18\x8f" \
  "\x18\xce\x10\x00\x18\xff\x10\x00" \
  "\x1a\xa3\x7f\x1a\xac\x1a\xee\x7f\x1a\xef\x7f\xcd\xac\x7f"

#define CPU12_CODE \
  "\x00\x04\x01\x00\x0c\x00\x80\x0e\x00\x80\x00\x11\x1e\x10\x00\x80\x00" \
  "\x3b\x4a\x10\x00\x04\x4b\x01\x04\x4f\x7f\x80\x00\x8f\x10\x00\xb7\x52" \
  "\xb7\xb1\xa6\x67\xa6\xfe\xa6\xf7\x18\x02\xe2\x30\x39\xe2\x10\x00" \
  "\x18\x0c\x30\x39\x10\x00\x18\x11\x18\x12\x10\x00\x18\x19\x00\x18\x1e\x00" \
  "\x18\x3e\x18\x3f\x00"

#define HD6301_CODE \
  "\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39"

#define M6809_CODE \
  "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81" \
  "\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00" \
  "\x11\xac\x99\x10\x00\x39" \
  \
  "\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10" \
  "\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86" \
  "\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00" \
  "\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00" \
  \
  "\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96" \
  "\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00" \
  "\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00"


#define HD6309_CODE \
  "\x01\x10\x10\x62\x10\x10\x7b\x10\x10\x00\xcd\x49\x96\x02\xd2" \
  "\x10\x30\x23\x10\x38\x10\x3b\x10\x53\x10\x5d" \
  "\x11\x30\x43\x10\x11\x37\x25\x10\x11\x38\x12\x11\x39\x23\x11\x3b\x34" \
  "\x11\x8e\x10\x00\x11\xaf\x10\x11\xab\x10\x11\xf6\x80\x00"

	struct platform platforms[] = {
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6301),
			(unsigned char *)HD6301_CODE,
			sizeof(HD6301_CODE) - 1,
			"M680X_HD6301",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6309),
			(unsigned char *)HD6309_CODE,
			sizeof(HD6309_CODE) - 1,
			"M680X_HD6309",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6800),
			(unsigned char *)M6800_CODE,
			sizeof(M6800_CODE) - 1,
			"M680X_M6800",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6801),
			(unsigned char *)M6801_CODE,
			sizeof(M6801_CODE) - 1,
			"M680X_M6801",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6805),
			(unsigned char *)M6805_CODE,
			sizeof(M6805_CODE) - 1,
			"M680X_M68HC05",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6808),
			(unsigned char *)M6808_CODE,
			sizeof(M6808_CODE) - 1,
			"M680X_M68HC08",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6809),
			(unsigned char *)M6809_CODE,
			sizeof(M6809_CODE) - 1,
			"M680X_M6809",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6811),
			(unsigned char *)M6811_CODE,
			sizeof(M6811_CODE) - 1,
			"M680X_M68HC11",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_CPU12),
			(unsigned char *)CPU12_CODE,
			sizeof(CPU12_CODE) - 1,
			"M680X_CPU12",
		},
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_HCS08),
			(unsigned char *)HCS08_CODE,
			sizeof(HCS08_CODE) - 1,
			"M680X_HCS08",
		},
	};

	uint64_t address = 0x1000;
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
				printf("0x%04x: ", (uint16_t)insn[j].address);
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
