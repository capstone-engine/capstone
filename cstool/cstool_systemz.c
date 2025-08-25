/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_systemz(csh handle, cs_insn *ins)
{
	cs_systemz *systemz;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	systemz = &(ins->detail->systemz);
	if (systemz->op_count)
		printf("\top_count: %u\n", systemz->op_count);

	for (i = 0; i < systemz->op_count; i++) {
		cs_systemz_op *op = &(systemz->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case SYSTEMZ_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case SYSTEMZ_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n",
			       i, op->imm);
			break;
		case SYSTEMZ_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != SYSTEMZ_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != SYSTEMZ_REG_INVALID)
				printf("\t\t\toperands[%u].mem.index: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.index));
			if (op->mem.length != 0) {
				printf("\t\t\toperands[%u].mem.length: 0x%" PRIx64
				       "\n",
				       i, op->mem.length);
			}
			printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n",
			       i, op->mem.disp);
			switch (op->mem.am) {
			default:
				printf("\t\t\toperands[%u].mem.am: UNHANDLED\n",
				       i);
				break;
			case SYSTEMZ_AM_BD:
				printf("\t\t\toperands[%u].mem.am: SYSTEMZ_AM_BD\n",
				       i);
				break;
			case SYSTEMZ_AM_BDX:
				printf("\t\t\toperands[%u].mem.am: SYSTEMZ_AM_BDX\n",
				       i);
				break;
			case SYSTEMZ_AM_BDL:
				printf("\t\t\toperands[%u].mem.am: SYSTEMZ_AM_BDL\n",
				       i);
				break;
			case SYSTEMZ_AM_BDR:
				printf("\t\t\toperands[%u].mem.am: SYSTEMZ_AM_BDR\n",
				       i);
				break;
			case SYSTEMZ_AM_BDV:
				printf("\t\t\toperands[%u].mem.am: SYSTEMZ_AM_BDV\n",
				       i);
				break;
			}
			break;
		}
		switch (op->access) {
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

	if (systemz->cc != SYSTEMZ_CC_INVALID)
		printf("\tCode condition: %u\n", systemz->cc);
}
