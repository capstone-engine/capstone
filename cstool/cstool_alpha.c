#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_alpha(csh handle, cs_insn *ins)
{
	cs_alpha *alpha;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	alpha = &(ins->detail->alpha);

	if (alpha->op_count)
		printf("\top_count: %u\n", alpha->op_count);

	for (i = 0; i < alpha->op_count; i++) {
		cs_alpha_op *op = &(alpha->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ALPHA_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case ALPHA_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       op->imm);
			break;
		}

		// Print out all registers accessed by this instruction (either implicit or
		// explicit)
		if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
				    regs_write, &regs_write_count)) {
			if (regs_read_count) {
				printf("\tRegisters read:");
				for (i = 0; i < regs_read_count; i++) {
					printf(" %s",
					       cs_reg_name(handle,
							   regs_read[i]));
				}
				printf("\n");
			}

			if (regs_write_count) {
				printf("\tRegisters modified:");
				for (i = 0; i < regs_write_count; i++) {
					printf(" %s",
					       cs_reg_name(handle,
							   regs_write[i]));
				}
				printf("\n");
			}
		}
	}
}