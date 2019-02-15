/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

static const char* get_bc_name(int bc)
{
	switch(bc) {
		default:
		case PPC_BC_INVALID:
			return ("invalid");
		case PPC_BC_LT:
			return ("lt");
		case PPC_BC_LE:
			return ("le");
		case PPC_BC_EQ:
			return ("eq");
		case PPC_BC_GE:
			return ("ge");
		case PPC_BC_GT:
			return ("gt");
		case PPC_BC_NE:
			return ("ne");
		case PPC_BC_UN:
			return ("un");
		case PPC_BC_NU:
			return ("nu");
		case PPC_BC_SO:
			return ("so");
		case PPC_BC_NS:
			return ("ns");
	}
}

char *get_detail_ppc(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_ppc *ppc;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	ppc = &(ins->detail->ppc);
	if (ppc->op_count)
		add_str(&result, " ; op_count: %u", ppc->op_count);

	for (i = 0; i < ppc->op_count; i++) {
		cs_ppc_op *op = &(ppc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case PPC_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case PPC_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%"PRIx64"", i, op->imm);
				break;
			case PPC_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != PPC_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);

				break;
			case PPC_OP_CRX:
				add_str(&result, " ; operands[%u].type: CRX", i);
				add_str(&result, " ; operands[%u].crx.scale: %d", i, op->crx.scale);
				add_str(&result, " ; operands[%u].crx.reg: %s", i, cs_reg_name(*handle, op->crx.reg));
				add_str(&result, " ; operands[%u].crx.cond: %s", i, get_bc_name(op->crx.cond));
				break;
		}
	}

	if (ppc->bc != 0)
		add_str(&result, " ; Branch code: %u", ppc->bc);

	if (ppc->bh != 0)
		add_str(&result, " ; Branch hint: %u", ppc->bh);

	if (ppc->update_cr0)
		add_str(&result, " ; Update-CR0: True");

	return result;
}

