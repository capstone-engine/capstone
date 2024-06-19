/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */
/*    Jiajie Chen <c@jia.je>, 2013-2024 */

#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_loongarch(csh handle, cs_insn *ins)
{
	cs_loongarch *loongarch;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	uint8_t access;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	loongarch = &(ins->detail->loongarch);
	if (loongarch->op_count)
		printf("\top_count: %u\n", loongarch->op_count);

	for (i = 0; i < loongarch->op_count; i++) {
		cs_loongarch_op *op = &(loongarch->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case LOONGARCH_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case LOONGARCH_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%lx\n", i,
			       (long)op->imm);
			break;
		case LOONGARCH_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != LOONGARCH_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != LOONGARCH_REG_INVALID)
				printf("\t\t\toperands[%u].mem.index: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.index));
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%lx\n",
				       i, (long)op->mem.disp);

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
