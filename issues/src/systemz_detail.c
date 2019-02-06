#include "factory.h"

char *get_detail_sysz(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_sysz *sysz;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	sysz = &(ins->detail->sysz);
	if (sysz->op_count)
		addStr(result, " | op_count: %u", sysz->op_count);

	for (i = 0; i < sysz->op_count; i++) {
		cs_sysz_op *op = &(sysz->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SYSZ_OP_REG:
				addStr(result, " | operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case SYSZ_OP_ACREG:
				addStr(result, " | operands[%u].type: ACREG = %u", i, op->reg);
				break;
			case SYSZ_OP_IMM:
				addStr(result, " | operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case SYSZ_OP_MEM:
				addStr(result, " | operands[%u].type: MEM", i);
				if (op->mem.base != SYSZ_REG_INVALID)
					addStr(result, " | operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != SYSZ_REG_INVALID)
					addStr(result, " | operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.length != 0)
					addStr(result, " | operands[%u].mem.length: 0x%" PRIx64 "", i, op->mem.length);
				if (op->mem.disp != 0)
					addStr(result, " | operands[%u].mem.disp: 0x%" PRIx64 "", i, op->mem.disp);

				break;
		}
	}

	if (sysz->cc != 0)
		addStr(result, " | Code condition: %u", sysz->cc);

	return result;
}

