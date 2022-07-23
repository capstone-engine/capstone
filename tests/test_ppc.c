/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

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

static const char* get_bc_name(int bc)
{
	switch(bc) {
		default:
		case PPC_BC_INVALID:
			return ("invalid");
		case PPC_BC_LT:
			return ("lt");
		case PPC_BC_LE:
			return ("le");
		case PPC_BC_EQ:
			return ("eq");
		case PPC_BC_GE:
			return ("ge");
		case PPC_BC_GT:
			return ("gt");
		case PPC_BC_NE:
			return ("ne");
		case PPC_BC_UN:
			return ("un");
		case PPC_BC_NU:
			return ("nu");
		case PPC_BC_SO:
			return ("so");
		case PPC_BC_NS:
			return ("ns");
	}
}

static void print_insn_detail(cs_insn *ins)
{
	cs_ppc *ppc;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	ppc = &(ins->detail->ppc);
	if (ppc->op_count)
		printf("\top_count: %u\n", ppc->op_count);

	for (i = 0; i < ppc->op_count; i++) {
		cs_ppc_op *op = &(ppc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case PPC_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case PPC_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case PPC_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != PPC_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case PPC_OP_CRX:
				printf("\t\toperands[%u].type: CRX\n", i);
				printf("\t\t\toperands[%u].crx.scale: %d\n", i, op->crx.scale);
				printf("\t\t\toperands[%u].crx.reg: %s\n", i, cs_reg_name(handle, op->crx.reg));
				printf("\t\t\toperands[%u].crx.cond: %s\n", i, get_bc_name(op->crx.cond));
				break;
		}
	}

	if (ppc->bc != 0)
		printf("\tBranch code: %u\n", ppc->bc);

	if (ppc->bh != 0)
		printf("\tBranch hint: %u\n", ppc->bh);

	if (ppc->update_cr0)
		printf("\tUpdate-CR0: True\n");

	printf("\n");
}

static void test()
{
#define PPC_CODE "\x43\x20\x0c\x07\x41\x56\xff\x17\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14"
#define PPC_CODE2 "\x10\x60\x2a\x10\x10\x64\x28\x88\x7c\x4a\x5d\x0f"
#define PPC_CODE3 "\x10\x00\x1f\xec\xe0\x6d\x80\x04\xe4\x6d\x80\x04\x10\x60\x1c\x4c\x10\x60\x1c\x0c\xf0\x6d\x80\x04\xf4\x6d\x80\x04\x10\x60\x1c\x4e\x10\x60\x1c\x0e\x10\x60\x1a\x10\x10\x60\x1a\x11\x10\x63\x20\x2a\x10\x63\x20\x2b\x10\x83\x20\x40\x10\x83\x20\xC0\x10\x83\x20\x00\x10\x83\x20\x80\x10\x63\x20\x24\x10\x63\x20\x25\x10\x63\x29\x3a\x10\x63\x29\x3b\x10\x63\x29\x1c\x10\x63\x29\x1d\x10\x63\x29\x1e\x10\x63\x29\x1f\x10\x63\x24\x20\x10\x63\x24\x21\x10\x63\x24\x60\x10\x63\x24\x61\x10\x63\x24\xA0\x10\x63\x24\xA1\x10\x63\x24\xE0\x10\x63\x24\xE1\x10\x60\x20\x90\x10\x60\x20\x91\x10\x63\x29\x38\x10\x63\x29\x39\x10\x63\x01\x32\x10\x63\x01\x33\x10\x63\x01\x18\x10\x63\x01\x19\x10\x63\x01\x1A\x10\x63\x01\x1B\x10\x60\x19\x10\x10\x60\x19\x11\x10\x60\x18\x50\x10\x60\x18\x51\x10\x63\x29\x3e\x10\x63\x29\x3f\x10\x63\x29\x3c\x10\x63\x29\x3d\x10\x60\x18\x30\x10\x60\x18\x31\x10\x60\x18\x34\x10\x60\x18\x35\x10\x63\x29\x2e\x10\x63\x29\x2f\x10\x63\x20\x28\x10\x63\x20\x29\x10\x63\x29\x14\x10\x63\x29\x15\x10\x63\x29\x16\x10\x63\x29\x17"

	struct platform platforms[] = {
		{
			CS_ARCH_PPC,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)PPC_CODE,
			sizeof(PPC_CODE) - 1,
			"PPC-64",
		},
		{
			CS_ARCH_PPC,
			(cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_QPX),
			(unsigned char*)PPC_CODE2,
			sizeof(PPC_CODE2) - 1,
			"PPC-64 + QPX",
		},
		{
			CS_ARCH_PPC,
			(cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_PS),
			(unsigned char*)PPC_CODE3,
			sizeof(PPC_CODE3) - 1,
			"PPC + PS",
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
