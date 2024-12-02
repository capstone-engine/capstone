#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_arc(csh handle, cs_insn *ins)
{
	cs_arc *arc;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	uint8_t access;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arc = &(ins->detail->arc);
	if (arc->op_count)
		printf("\top_count: %u\n", arc->op_count);

	for (i = 0; i < arc->op_count; i++) {
		cs_arc_op *op = &(arc->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ARC_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case ARC_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%lx\n", i,
			       (long)op->imm);
			break;
		}

		access = op->access;
		switch (access) {
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

	if (ins->detail->writeback)
		printf("\tWrite-back: True\n");

	/* print all registers that are involved in this instruction */
	if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
			    regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for (i = 0; i < regs_read_count; i++)
				printf(" %s",
				       cs_reg_name(handle, regs_read[i]));
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for (i = 0; i < regs_write_count; i++)
				printf(" %s",
				       cs_reg_name(handle, regs_write[i]));
			printf("\n");
		}
	}
}
