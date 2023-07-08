/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>

#include <capstone/capstone.h>
#include "capstone/ppc.h"
#include "cstool.h"

static const char* get_pred_name(ppc_pred pred)
{
	switch(pred) {
		default:
			return ("invalid");
		case PPC_PRED_LT:
		case PPC_PRED_LT_MINUS:
		case PPC_PRED_LT_PLUS:
			return ("lt");
		case PPC_PRED_LE:
		case PPC_PRED_LE_MINUS:
		case PPC_PRED_LE_PLUS:
			return ("le");
		case PPC_PRED_EQ:
		case PPC_PRED_EQ_MINUS:
		case PPC_PRED_EQ_PLUS:
			return ("eq");
		case PPC_PRED_GE:
		case PPC_PRED_GE_MINUS:
		case PPC_PRED_GE_PLUS:
			return ("ge");
		case PPC_PRED_GT:
		case PPC_PRED_GT_MINUS:
		case PPC_PRED_GT_PLUS:
			return ("gt");
		case PPC_PRED_NE:
		case PPC_PRED_NE_MINUS:
		case PPC_PRED_NE_PLUS:
			return ("ne");
		case PPC_PRED_UN:
		case PPC_PRED_UN_MINUS:
		case PPC_PRED_UN_PLUS:
			return ("un");
		case PPC_PRED_NU:
		case PPC_PRED_NU_MINUS:
		case PPC_PRED_NU_PLUS:
			return ("nu");
		case PPC_PRED_NZ:
		case PPC_PRED_NZ_MINUS:
		case PPC_PRED_NZ_PLUS:
			return ("nz");
		case PPC_PRED_Z:
		case PPC_PRED_Z_MINUS:
		case PPC_PRED_Z_PLUS:
			return ("z");
		case PPC_PRED_SO:
			return ("so");
		case PPC_PRED_NS:
			return ("ns");
		case PPC_PRED_BIT_SET:
			return "bit-set";
		case PPC_PRED_BIT_UNSET:
			return "bit-unset";
	}
}

void print_insn_detail_ppc(csh handle, cs_insn *ins)
{
	cs_ppc *ppc;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	ppc = &(ins->detail->ppc);
	if (ppc->op_count)
		printf("\top_count: %u\n", ppc->op_count);

	for (i = 0; i < ppc->op_count; i++) {
		cs_ppc_op *op = &(ppc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case PPC_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case PPC_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%"PRIx64"\n", i, op->imm);
				break;
			case PPC_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != PPC_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.offset != PPC_REG_INVALID)
					printf("\t\t\toperands[%u].mem.offset: REG = %s\n", i,
						cs_reg_name(handle, op->mem.offset));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
		}
		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
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
			printf("\t\tcrX: %s\n", cs_reg_name(handle, ppc->bc.crX));
			printf("\t\tpred CR-bit: %s\n", get_pred_name(ppc->bc.pred_cr));
		}
		if (ppc->bc.pred_ctr != PPC_PRED_INVALID)
			printf("\t\tpred CTR: %s\n", get_pred_name(ppc->bc.pred_ctr));
		if (ppc->bc.hint != PPC_BH_INVALID)
			printf("\t\thint: %u\n", ppc->bc.hint);
	}

	if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
		printf("\tBranch hint: %u\n", ppc->bc.hint);

	if (ppc->update_cr0)
		printf("\tUpdate-CR0: True\n");
}
