#include "factory.h"

char *get_detail_mips(csh *handle, cs_mode mode, cs_insn *ins)
{
	int i;
	cs_mips *mips;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	mips = &(ins->detail->mips);
	if (mips->op_count)
		addStr(&result, " ; op_count: %u", mips->op_count);

	for (i = 0; i < mips->op_count; i++) {
		cs_mips_op *op = &(mips->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case MIPS_OP_REG:
				addStr(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case MIPS_OP_IMM:
				addStr(&result, " ; operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case MIPS_OP_MEM:
				addStr(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != MIPS_REG_INVALID)
					addStr(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.disp != 0)
					addStr(&result, " ; operands[%u].mem.disp: 0x%" PRIx64 "", i, op->mem.disp);

				break;
		}

	}

	return result;
}

