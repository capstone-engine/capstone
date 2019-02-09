#include "factory.h"

char *get_detail_sparc(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_sparc *sparc;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	sparc = &(ins->detail->sparc);
	if (sparc->op_count)
		addStr(&result, " | op_count: %u", sparc->op_count);

	for (i = 0; i < sparc->op_count; i++) {
		cs_sparc_op *op = &(sparc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SPARC_OP_REG:
				addStr(&result, " | operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case SPARC_OP_IMM:
				addStr(&result, " | operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case SPARC_OP_MEM:
				addStr(&result, " | operands[%u].type: MEM", i);
				if (op->mem.base != X86_REG_INVALID)
					addStr(&result, " | operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					addStr(&result, " | operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					addStr(&result, " | operands[%u].mem.disp: 0x%x", i, op->mem.disp);

				break;
		}
	}

	if (sparc->cc != 0)
		addStr(&result, " | Code condition: %u", sparc->cc);

	if (sparc->hint != 0)
		addStr(&result, " | Hint code: %u", sparc->hint);

	return result;
}

