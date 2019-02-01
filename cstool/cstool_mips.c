/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

void print_insn_detail_mips(csh handle, cs_insn *ins);

void print_insn_detail_mips(csh handle, cs_insn *ins)
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
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case MIPS_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != MIPS_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
						   i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);

				break;
		}

	}
}
