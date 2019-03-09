/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_riscv(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_riscv *riscv;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	riscv = &(ins->detail->riscv);
	if (riscv->op_count)
		add_str(&result, " ; op_count: %u", riscv->op_count);

	for (i = 0; i < riscv->op_count; i++) {
		cs_riscv_op *op = &(riscv->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case RISCV_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case RISCV_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case RISCV_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != RISCV_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s",
							i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);
				break;
		}
	}

	return result;
}

