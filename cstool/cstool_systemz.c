/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdio.h>

#include <capstone/capstone.h>

void print_insn_detail_sysz(csh handle, cs_insn *ins);

void print_insn_detail_sysz(csh handle, cs_insn *ins)
{
	cs_sysz *sysz;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	sysz = &(ins->detail->sysz);
	if (sysz->op_count)
		printf("\top_count: %u\n", sysz->op_count);

	for (i = 0; i < sysz->op_count; i++) {
		cs_sysz_op *op = &(sysz->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case SYSZ_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case SYSZ_OP_ACREG:
				printf("\t\toperands[%u].type: ACREG = %u\n", i, op->reg);
				break;
			case SYSZ_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case SYSZ_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != SYSZ_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != SYSZ_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.length != 0)
					printf("\t\t\toperands[%u].mem.length: 0x%" PRIx64 "\n", i, op->mem.length);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);

				break;
		}
	}

	if (sysz->cc != 0)
		printf("\tCode condition: %u\n", sysz->cc);
}
