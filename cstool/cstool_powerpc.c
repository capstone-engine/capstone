/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>

#include <capstone/capstone.h>
#include "cstool.h"

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
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case PPC_OP_CRX:
				printf("\t\toperands[%u].type: CRX\n", i);
				printf("\t\t\toperands[%u].crx.scale: %d\n", i, op->crx.scale);
				printf("\t\t\toperands[%u].crx.reg: %s\n", i, cs_reg_name(handle, op->crx.reg));
				printf("\t\t\toperands[%u].crx.cond: %s\n", i, get_bc_name(op->crx.cond));
				break;
		}
	}

	if (ppc->bc != 0)
		printf("\tBranch code: %u\n", ppc->bc);

	if (ppc->bh != 0)
		printf("\tBranch hint: %u\n", ppc->bh);

	if (ppc->update_cr0)
		printf("\tUpdate-CR0: True\n");
}
