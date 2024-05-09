/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

static const char* get_pred_name(int bc)
{
	switch(bc) {
		default:
		case PPC_PRED_LT:
			return ("lt");
		case PPC_PRED_LE:
			return ("le");
		case PPC_PRED_EQ:
			return ("eq");
		case PPC_PRED_GE:
			return ("ge");
		case PPC_PRED_GT:
			return ("gt");
		case PPC_PRED_NE:
			return ("ne");
		case PPC_PRED_UN:
			return ("so/un");
		case PPC_PRED_NU:
			return ("ns/nu");
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
		}
	}

	if (ppc->bc.pred_cr != PPC_PRED_INVALID ||
			ppc->bc.pred_ctr != PPC_PRED_INVALID) {
		printf("\tBranch:\n");
		printf("\t\tbi: %u\n", ppc->bc.bi);
		printf("\t\tbo: %u\n", ppc->bc.bo);
		if (ppc->bc.bh != PPC_BH_INVALID)
			printf("\t\tbh: %u\n", ppc->bc.bh);
		if (ppc->bc.pred_cr != PPC_PRED_INVALID) {
			printf("\t\tcrX: %s\n", cs_reg_name(*handle, ppc->bc.crX));
			printf("\t\tpred CR-bit: %s\n", get_pred_name(ppc->bc.pred_cr));
		}
		if (ppc->bc.pred_ctr != PPC_PRED_INVALID)
			printf("\t\tpred CTR: %s\n", get_pred_name(ppc->bc.pred_ctr));
		if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
			printf("\t\thint: %u\n", ppc->bc.hint);
	}

	if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
		printf("\tBranch hint: %u\n", ppc->bc.hint);

	if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
		add_str(&result, " ; Branch hint: %u", ppc->bc.hint);

	if (ppc->update_cr0)
		add_str(&result, " ; Update-CR0: True");

	return result;
}

