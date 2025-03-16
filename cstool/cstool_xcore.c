/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_xcore(csh handle, cs_insn *ins)
{
	cs_xcore *xcore;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	xcore = &(ins->detail->d.xcore);
	if (xcore->op_count)
		printf("\top_count: %u\n", xcore->op_count);

	for (i = 0; i < xcore->op_count; i++) {
		cs_xcore_op *op = &(xcore->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case XCORE_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->v.reg));
				break;
			case XCORE_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->v.imm);
				break;
			case XCORE_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->v.mem.base != XCORE_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->v.mem.base));
				if (op->v.mem.index != XCORE_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->v.mem.index));
				if (op->v.mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->v.mem.disp);
				if (op->v.mem.direct != 1)
					printf("\t\t\toperands[%u].mem.direct: -1\n", i);


				break;
		}
	}

	printf("\n");
}
