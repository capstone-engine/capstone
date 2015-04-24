/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>
#include "../myinttypes.h"

#include <capstone.h>
#include "test_utils.h"

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
};

static int total_errors = 0;

static csh handle;

static void print_insn_detail(cs_insn *ins)
{
	int i;
	cs_mips *mips;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	mips = &(ins->detail->mips);
	if (mips->op_count)
		printf("\top_count: %u\n", mips->op_count);

	for (i = 0; i < mips->op_count; i++) {
		cs_mips_op *op = &(mips->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case MIPS_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case MIPS_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%"PRIx64 "\n", i, op->imm);
				break;
			case MIPS_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);

				break;
		}

	}

	printf("\n");
}

static void test()
{
//#define MIPS_CODE "\x8f\xa2\x00\x00"
//#define MIPS_CODE "\x00\x00\xa7\xac\x10\x00\xa2\x8f"
//#define MIPS_CODE "\x21\x30\xe6\x70"	// clo $6, $7
//#define MIPS_CODE "\x00\x00\x00\x00" // nop
//#define MIPS_CODE "\xc6\x23\xe9\xe4"	// swc1	$f9, 0x23c6($7)
//#define MIPS_CODE "\x21\x38\x00\x01"	// move $7, $8
#define MIPS_CODE "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
//#define MIPS_CODE "\x04\x11\x00\x01"	// bal	0x8
#define MIPS_CODE2 "\x56\x34\x21\x34\xc2\x17\x01\x00"
#define MIPS_32R6M "\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0"
#define MIPS_32R6 "\xec\x80\x00\x19\x7c\x43\x22\xa0"

	struct platform platforms[] = {
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
			(unsigned char *)MIPS_CODE,
			sizeof(MIPS_CODE) - 1,
			"MIPS-32 (Big-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
			(unsigned char *)MIPS_CODE2,
			sizeof(MIPS_CODE2) - 1,
			"MIPS-64-EL (Little-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
			(unsigned char*)MIPS_32R6M,
			sizeof(MIPS_32R6M) - 1,
			"MIPS-32R6 | Micro (Big-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
			(unsigned char*)MIPS_32R6,
			sizeof(MIPS_32R6) - 1,
			"MIPS-32R6 (Big-endian)"
		},
	};

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < COUNTOF(platforms); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			total_errors++;
			continue;
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
				printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%"PRIx64":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			total_errors++;
		}

		printf("\n");

		cs_close(&handle);
	}
}

static void test_group_name()
{
	cs_err err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		total_errors++;
		return;
	}
	static struct group_name group_names[] = {
		{ MIPS_GRP_INVALID, NULL },
		{ MIPS_GRP_JUMP, "jump" },
		{ MIPS_GRP_JUMP+1, NULL },

		// architecture-specific groups
		{ MIPS_GRP_BITCOUNT-1, NULL },
		{ MIPS_GRP_BITCOUNT, "bitcount" },
		{ MIPS_GRP_DSP, "dsp" },
		{ MIPS_GRP_DSPR2, "dspr2" },
		{ MIPS_GRP_FPIDX, "fpidx" },
		{ MIPS_GRP_MSA, "msa" },
		{ MIPS_GRP_MIPS32R2, "mips32r2" },
		{ MIPS_GRP_MIPS64, "mips64" },
		{ MIPS_GRP_MIPS64R2, "mips64r2" },
		{ MIPS_GRP_SEINREG, "seinreg" },
		{ MIPS_GRP_STDENC, "stdenc" },
		{ MIPS_GRP_SWAP, "swap" },
		{ MIPS_GRP_MICROMIPS, "micromips" },
		{ MIPS_GRP_MIPS16MODE, "mips16mode" },
		{ MIPS_GRP_FP64BIT, "fp64bit" },
		{ MIPS_GRP_NONANSFPMATH, "nonansfpmath" },
		{ MIPS_GRP_NOTFP64BIT, "notfp64bit" },
		{ MIPS_GRP_NOTINMICROMIPS, "notinmicromips" },
		{ MIPS_GRP_NOTNACL, "notnacl" },

		{ MIPS_GRP_NOTMIPS32R6, "notmips32r6" },
		{ MIPS_GRP_NOTMIPS64R6, "notmips64r6" },
		{ MIPS_GRP_CNMIPS, "cnmips" },

		{ MIPS_GRP_MIPS32, "mips32" },
		{ MIPS_GRP_MIPS32R6, "mips32r6" },
		{ MIPS_GRP_MIPS64R6, "mips64r6" },

		{ MIPS_GRP_MIPS2, "mips2" },
		{ MIPS_GRP_MIPS3, "mips3" },
		{ MIPS_GRP_MIPS3_32, "mips3_32"},
		{ MIPS_GRP_MIPS3_32R2, "mips3_32r2" },

		{ MIPS_GRP_MIPS4_32, "mips4_32" },
		{ MIPS_GRP_MIPS4_32R2, "mips4_32r2" },
		{ MIPS_GRP_MIPS5_32R2, "mips5_32r2" },

		{ MIPS_GRP_GP32BIT, "gp32bit" },
		{ MIPS_GRP_GP64BIT, "gp64bit" },
		{ MIPS_GRP_GP64BIT+1, NULL },
	};
	test_groups_common(handle, &total_errors, group_names, COUNTOF(group_names));
	cs_close(&handle);
}

int main()
{
	test();
	test_group_name();
	return total_errors;
}
