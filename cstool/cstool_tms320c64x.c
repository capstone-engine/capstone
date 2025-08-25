/* Capstone Disassembler Engine */
/* By Fotis Loukos <me@fotisl.com>, 2017 */

#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_tms320c64x(csh handle, cs_insn *ins)
{
	cs_tms320c64x *tms320c64x;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	tms320c64x = &(ins->detail->tms320c64x);
	if (tms320c64x->op_count)
		printf("\top_count: %u\n", tms320c64x->op_count);

	for (i = 0; i < tms320c64x->op_count; i++) {
		cs_tms320c64x_op *op = &(tms320c64x->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case TMS320C64X_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case TMS320C64X_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       op->imm);
			break;
		case TMS320C64X_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != TMS320C64X_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.base));
			printf("\t\t\toperands[%u].mem.disptype: ", i);
			if (op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
				printf("Invalid\n");
				printf("\t\t\toperands[%u].mem.disp: %u\n", i,
				       op->mem.disp);
			}
			if (op->mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
				printf("Constant\n");
				printf("\t\t\toperands[%u].mem.disp: %u\n", i,
				       op->mem.disp);
			}
			if (op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
				printf("Register\n");
				printf("\t\t\toperands[%u].mem.disp: %s\n", i,
				       cs_reg_name(handle, op->mem.disp));
			}
			printf("\t\t\toperands[%u].mem.unit: %u\n", i,
			       op->mem.unit);
			printf("\t\t\toperands[%u].mem.direction: ", i);
			if (op->mem.direction == TMS320C64X_MEM_DIR_INVALID)
				printf("Invalid\n");
			if (op->mem.direction == TMS320C64X_MEM_DIR_FW)
				printf("Forward\n");
			if (op->mem.direction == TMS320C64X_MEM_DIR_BW)
				printf("Backward\n");
			printf("\t\t\toperands[%u].mem.modify: ", i);
			if (op->mem.modify == TMS320C64X_MEM_MOD_INVALID)
				printf("Invalid\n");
			if (op->mem.modify == TMS320C64X_MEM_MOD_NO)
				printf("No\n");
			if (op->mem.modify == TMS320C64X_MEM_MOD_PRE)
				printf("Pre\n");
			if (op->mem.modify == TMS320C64X_MEM_MOD_POST)
				printf("Post\n");
			printf("\t\t\toperands[%u].mem.scaled: %u\n", i,
			       op->mem.scaled);

			break;
		case TMS320C64X_OP_REGPAIR:
			printf("\t\toperands[%u].type: REGPAIR = %s:%s\n", i,
			       cs_reg_name(handle, op->reg + 1),
			       cs_reg_name(handle, op->reg));
			break;
		}
	}

	printf("\tFunctional unit: ");
	switch (tms320c64x->funit.unit) {
	case TMS320C64X_FUNIT_D:
		printf("D%u\n", tms320c64x->funit.side);
		break;
	case TMS320C64X_FUNIT_L:
		printf("L%u\n", tms320c64x->funit.side);
		break;
	case TMS320C64X_FUNIT_M:
		printf("M%u\n", tms320c64x->funit.side);
		break;
	case TMS320C64X_FUNIT_S:
		printf("S%u\n", tms320c64x->funit.side);
		break;
	case TMS320C64X_FUNIT_NO:
		printf("No Functional Unit\n");
		break;
	default:
		printf("Unknown (Unit %u, Side %u)\n", tms320c64x->funit.unit,
		       tms320c64x->funit.side);
		break;
	}
	if (tms320c64x->funit.crosspath == 1)
		printf("\tCrosspath: 1\n");

	if (tms320c64x->condition.reg != TMS320C64X_REG_INVALID)
		printf("\tCondition: [%c%s]\n",
		       (tms320c64x->condition.zero == 1) ? '!' : ' ',
		       cs_reg_name(handle, tms320c64x->condition.reg));
	printf("\tParallel: %s\n",
	       (tms320c64x->parallel == 1) ? "true" : "false");

	printf("\n");
}
