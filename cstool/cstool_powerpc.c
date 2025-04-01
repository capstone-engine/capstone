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
		case PPC_PRED_LT_RESERVED:
			return ("lt");
		case PPC_PRED_LE:
		case PPC_PRED_LE_MINUS:
		case PPC_PRED_LE_PLUS:
		case PPC_PRED_LE_RESERVED:
			return ("le");
		case PPC_PRED_EQ:
		case PPC_PRED_EQ_MINUS:
		case PPC_PRED_EQ_PLUS:
		case PPC_PRED_EQ_RESERVED:
			return ("eq");
		case PPC_PRED_GE:
		case PPC_PRED_GE_MINUS:
		case PPC_PRED_GE_PLUS:
		case PPC_PRED_GE_RESERVED:
			return ("ge");
		case PPC_PRED_GT:
		case PPC_PRED_GT_MINUS:
		case PPC_PRED_GT_PLUS:
		case PPC_PRED_GT_RESERVED:
			return ("gt");
		case PPC_PRED_NE:
		case PPC_PRED_NE_MINUS:
		case PPC_PRED_NE_PLUS:
		case PPC_PRED_NE_RESERVED:
			return ("ne");
		case PPC_PRED_UN: // PPC_PRED_SO
		case PPC_PRED_UN_MINUS:
		case PPC_PRED_UN_PLUS:
		case PPC_PRED_UN_RESERVED:
			return ("so/un");
		case PPC_PRED_NU: // PPC_PRED_NS
		case PPC_PRED_NU_MINUS:
		case PPC_PRED_NU_PLUS:
		case PPC_PRED_NU_RESERVED:
			return ("ns/nu");
		case PPC_PRED_NZ:
		case PPC_PRED_NZ_MINUS:
		case PPC_PRED_NZ_PLUS:
		case PPC_PRED_NZ_RESERVED:
			return ("nz");
		case PPC_PRED_Z:
		case PPC_PRED_Z_MINUS:
		case PPC_PRED_Z_PLUS:
		case PPC_PRED_Z_RESERVED:
			return ("z");
		case PPC_PRED_BIT_SET:
			return "bit-set";
		case PPC_PRED_BIT_UNSET:
			return "bit-unset";
	}
}

static const char *get_pred_hint(ppc_br_hint at) {
	switch (at) {
	default:
		return "invalid";
	case PPC_BR_NOT_GIVEN:
		return "not-given";
	case PPC_BR_TAKEN:
		return "likely-taken";
	case PPC_BR_NOT_TAKEN:
		return "likely-not-taken";
	case PPC_BR_RESERVED:
		return "reserved";
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
			case CS_AC_READ_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}
	}

	if (ppc->bc.pred_cr != PPC_PRED_INVALID ||
			ppc->bc.pred_ctr != PPC_PRED_INVALID) {
		printf("\tBranch:\n");
		printf("\t\tbi: %u\n", ppc->bc.bi);
		printf("\t\tbo: %u\n", ppc->bc.bo);
		if (ppc->bc.bh != PPC_BH_INVALID) {
			char const* msg = NULL;
			switch(ppc->bc.bh) {
				case PPC_BH_SUBROUTINE_RET:
					msg = "subroutine return";
					break;
				case PPC_BH_NO_SUBROUTINE_RET:
					msg = "not a subroutine return";
					break;
				case PPC_BH_NOT_PREDICTABLE:
					msg = "unpredictable";
					break;
				case PPC_BH_RESERVED:
					msg = "reserved";
					break;
				case PPC_BH_INVALID: break;
			}
			printf("\t\tbh: %s\n", msg);
    }
		if (ppc->bc.pred_cr != PPC_PRED_INVALID) {
			printf("\t\tcrX: %s\n", cs_reg_name(handle, ppc->bc.crX));
			printf("\t\tpred CR-bit: %s\n", get_pred_name(ppc->bc.pred_cr));
		}
		if (ppc->bc.pred_ctr != PPC_PRED_INVALID)
			printf("\t\tpred CTR: %s\n", get_pred_name(ppc->bc.pred_ctr));
		if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
			printf("\t\thint: %s\n", get_pred_hint(ppc->bc.hint));
	}

	if (ppc->bc.hint != PPC_BR_NOT_GIVEN)
		printf("\tBranch hint (at bits): %u\n", ppc->bc.hint);

	if (ppc->update_cr0)
		printf("\tUpdate-CR0: True\n");

	uint16_t *regs_read = ins->detail->regs_read;
	uint16_t *regs_write = ins->detail->regs_write;
	uint8_t regs_read_count = ins->detail->regs_read_count;
	uint8_t regs_write_count = ins->detail->regs_write_count;
	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (regs_read_count) {
		printf("\tImplicit registers read:");
		for(i = 0; i < regs_read_count; i++) {
			printf(" %s", cs_reg_name(handle, regs_read[i]));
		}
		printf("\n");
	}

	if (regs_write_count) {
		printf("\tImplicit registers modified:");
		for(i = 0; i < regs_write_count; i++) {
			printf(" %s", cs_reg_name(handle, regs_write[i]));
		}
		printf("\n");
	}
}
