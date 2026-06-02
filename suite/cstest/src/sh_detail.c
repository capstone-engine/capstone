/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

static const char *get_mem_address_name(sh_op_mem_type address)
{
	switch (address) {
	default:
		break;
	case SH_OP_MEM_REG_IND:
		return "Register Indirect";
	case SH_OP_MEM_REG_POST:
		return "Register Indirect with Postincrement";
	case SH_OP_MEM_REG_PRE:
		return "Register Indirect with Predecrement";
	case SH_OP_MEM_REG_DISP:
		return "Register Indirect with displacement";
	case SH_OP_MEM_REG_R0:
		return "R0 indexed";
	case SH_OP_MEM_GBR_DISP:
		return "GBR based displacement";
	case SH_OP_MEM_GBR_R0:
		return "GBR based R0 indexed";
	case SH_OP_MEM_PCR:
		return "PC relative";
	case SH_OP_MEM_TBR_DISP:
		return "TBR based displacement";
	}
	return "Invalid";
}

char *get_detail_sh(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_sh *sh;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	sh = &(ins->detail->sh);
	if (sh->op_count)
		add_str(&result, " ; op_count: %u", sh->op_count);

	for (i = 0; i < sh->op_count; i++) {
		cs_sh_op *op = &(sh->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case SH_OP_REG:
			add_str(&result, " ; operands[%u].type: REG = %s", i,
				cs_reg_name(*handle, op->reg));
			break;
		case SH_OP_IMM:
			add_str(&result, " ; operands[%u].type: IMM = 0x%llx", i,
				(unsigned long long)op->imm);
			break;
		case SH_OP_MEM:
			add_str(&result, " ; operands[%u].type: MEM", i);
			if (op->mem.reg != SH_REG_INVALID)
				add_str(&result, " ; operands[%u].mem.reg: REG = %s",
					i, cs_reg_name(*handle, op->mem.reg));
			if (op->mem.disp != 0)
				add_str(&result, " ; operands[%u].mem.disp: 0x%x",
					i, op->mem.disp);
			add_str(&result, " ; address mode: %s",
				get_mem_address_name(op->mem.address));
			break;
		}
	}

	return result;
}
