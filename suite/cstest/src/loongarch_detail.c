/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */
/*    Jiajie Chen <c@jia.je>, 2024 */


#include "factory.h"

char *get_detail_loongarch(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_loongarch *loongarch;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	loongarch = &(ins->detail->loongarch);
	if (loongarch->op_count)
		add_str(&result, " ; op_count: %u", loongarch->op_count);

	for (i = 0; i < loongarch->op_count; i++) {
		cs_loongarch_op *op = &(loongarch->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case LOONGARCH_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case LOONGARCH_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case LOONGARCH_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != LOONGARCH_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s",
							i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != LOONGARCH_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s",
							i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);
				break;
		}
	}

	return result;
}

