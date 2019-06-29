/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_sparc(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_sparc *sparc;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	sparc = &(ins->detail->sparc);
	if (sparc->op_count)
		add_str(&result, " ; op_count: %u", sparc->op_count);

	for (i = 0; i < sparc->op_count; i++) {
		cs_sparc_op *op = &(sparc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SPARC_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case SPARC_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case SPARC_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != X86_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);

				break;
		}
	}

	if (sparc->cc != 0)
		add_str(&result, " ; Code condition: %u", sparc->cc);

	if (sparc->hint != 0)
		add_str(&result, " ; Hint code: %u", sparc->hint);

	return result;
}

