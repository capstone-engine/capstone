#include "factory.h"

char *get_detail_xcore(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_xcore *xcore;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	xcore = &(ins->detail->xcore);
	if (xcore->op_count)
		addStr(&result, " ; op_count: %u", xcore->op_count);

	for (i = 0; i < xcore->op_count; i++) {
		cs_xcore_op *op = &(xcore->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case XCORE_OP_REG:
				addStr(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case XCORE_OP_IMM:
				addStr(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case XCORE_OP_MEM:
				addStr(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != XCORE_REG_INVALID)
					addStr(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != XCORE_REG_INVALID)
					addStr(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					addStr(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);
				if (op->mem.direct != 1)
					addStr(&result, " ; operands[%u].mem.direct: -1", i);


				break;
		}
	}

	return result;
}

