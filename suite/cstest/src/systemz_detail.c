/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_sysz(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_sysz *sysz;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	sysz = &(ins->detail->sysz);
	if (sysz->op_count)
		add_str(&result, " ; op_count: %u", sysz->op_count);

	for (i = 0; i < sysz->op_count; i++) {
		cs_sysz_op *op = &(sysz->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SYSZ_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case SYSZ_OP_ACREG:
				add_str(&result, " ; operands[%u].type: ACREG = %u", i, op->reg);
				break;
			case SYSZ_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case SYSZ_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != SYSZ_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != SYSZ_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.length != 0)
					add_str(&result, " ; operands[%u].mem.length: 0x%" PRIx64 "", i, op->mem.length);
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%" PRIx64 "", i, op->mem.disp);

				break;
		}
	}

	if (sysz->cc != 0)
		add_str(&result, " ; Code condition: %u", sysz->cc);

	return result;
}

