/* Capstone Disassembly Engine */
/* TMS320C64x Backend by Fotis Loukos <me@fotisl.com> 2016 */

#include <stdio.h>

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
	cs_tms320c64x *tms320c64x;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	tms320c64x = &(ins->detail->tms320c64x);
	if (tms320c64x->op_count)
		printf("\top_count: %u\n", tms320c64x->op_count);

	for (i = 0; i < tms320c64x->op_count; i++) {
		cs_tms320c64x_op *op = &(tms320c64x->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case TMS320C64X_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case TMS320C64X_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case TMS320C64X_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != TMS320C64X_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				printf("\t\t\toperands[%u].mem.disptype: ", i);
				if(op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
					printf("Invalid\n");
					printf("\t\t\toperands[%u].mem.disp: %u\n", i, op->mem.disp);
				}
				if(op->mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
					printf("Constant\n");
					printf("\t\t\toperands[%u].mem.disp: %u\n", i, op->mem.disp);
				}
				if(op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
					printf("Register\n");
					printf("\t\t\toperands[%u].mem.disp: %s\n", i, cs_reg_name(handle, op->mem.disp));
				}
				printf("\t\t\toperands[%u].mem.unit: %u\n", i, op->mem.unit);
				printf("\t\t\toperands[%u].mem.direction: ", i);
				if(op->mem.direction == TMS320C64X_MEM_DIR_INVALID)
					printf("Invalid\n");
				if(op->mem.direction == TMS320C64X_MEM_DIR_FW)
					printf("Forward\n");
				if(op->mem.direction == TMS320C64X_MEM_DIR_BW)
					printf("Backward\n");
				printf("\t\t\toperands[%u].mem.modify: ", i);
				if(op->mem.modify == TMS320C64X_MEM_MOD_INVALID)
					printf("Invalid\n");
				if(op->mem.modify == TMS320C64X_MEM_MOD_NO)
					printf("No\n");
				if(op->mem.modify == TMS320C64X_MEM_MOD_PRE)
					printf("Pre\n");
				if(op->mem.modify == TMS320C64X_MEM_MOD_POST)
					printf("Post\n");
				printf("\t\t\toperands[%u].mem.scaled: %u\n", i, op->mem.scaled);


				break;
			case TMS320C64X_OP_REGPAIR:
				printf("\t\toperands[%u].type: REGPAIR = %s:%s\n", i, cs_reg_name(handle, op->reg + 1), cs_reg_name(handle, op->reg));
				break;
		}
	}

	printf("\tFunctional unit: ");
	switch(tms320c64x->funit.unit) {
		case TMS320C64X_FUNIT_D:
			printf("D%u\n", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_L:
			printf("L%u\n", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_M:
			printf("M%u\n", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_S:
			printf("S%u\n", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_NO:
			printf("No Functional Unit\n");
			break;
		default:
			printf("Unknown (Unit %u, Side %u)\n", tms320c64x->funit.unit, tms320c64x->funit.side);
			break;
	}
	if(tms320c64x->funit.crosspath == 1)
		printf("\tCrosspath: 1\n");

	if(tms320c64x->condition.reg != TMS320C64X_REG_INVALID)
		printf("\tCondition: [%c%s]\n", (tms320c64x->condition.zero == 1) ? '!' : ' ', cs_reg_name(handle, tms320c64x->condition.reg));
	printf("\tParallel: %s\n", (tms320c64x->parallel == 1) ? "true" : "false");

	printf("\n");
}

static void test()
{
#define TMS320C64X_CODE "\x01\xac\x88\x40\x81\xac\x88\x43\x00\x00\x00\x00\x02\x90\x32\x96\x02\x80\x46\x9e\x05\x3c\x83\xe6\x0b\x0c\x8b\x24"

	struct platform platforms[] = {
		{
			CS_ARCH_TMS320C64X,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)TMS320C64X_CODE,
			sizeof(TMS320C64X_CODE) - 1,
			"TMS320C64x",
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
