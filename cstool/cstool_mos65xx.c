#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

void print_insn_detail_mos65xx(csh handle, cs_insn *ins);


static const char *get_am_name(mos65xx_address_mode mode)
{
	switch(mode) {
		default:
		case MOS65XX_AM_NONE:
			return "No address mode";
		case MOS65XX_AM_IMP:
			return "implied";
		case MOS65XX_AM_ACC:
			return "accumulator";
		case MOS65XX_AM_IMM:
			return "immediate value";
		case MOS65XX_AM_REL:
			return "relative";
		case MOS65XX_AM_INT:
			return "interrupt signature";
		case MOS65XX_AM_BLOCK:
			return "block move";
		case MOS65XX_AM_ZP:
			return "zero page";
		case MOS65XX_AM_ZP_X:
			return "zero page indexed with x";
		case MOS65XX_AM_ZP_Y:
			return "zero page indexed with y";
		case MOS65XX_AM_ZP_REL:
			return "relative bit branch";
		case MOS65XX_AM_ZP_IND:
			return "zero page indirect";
		case MOS65XX_AM_ZP_X_IND:
			return "zero page indexed with x indirect";
		case MOS65XX_AM_ZP_IND_Y:
			return "zero page indirect indexed with y";
		case MOS65XX_AM_ZP_IND_LONG:
			return "zero page indirect long";
		case MOS65XX_AM_ZP_IND_LONG_Y:
			return "zero page indirect long indexed with y";
		case MOS65XX_AM_ABS:
			return "absolute";
		case MOS65XX_AM_ABS_X:
			return "absolute indexed with x";
		case MOS65XX_AM_ABS_Y:
			return "absolute indexed with y";
		case MOS65XX_AM_ABS_IND:
			return "absolute indirect";
		case MOS65XX_AM_ABS_X_IND:
			return "absolute indexed with x indirect";
		case MOS65XX_AM_ABS_IND_LONG:
			return "absolute indirect long";
		case MOS65XX_AM_ABS_LONG:
			return "absolute long";
		case MOS65XX_AM_ABS_LONG_X:
			return "absolute long indexed with x";
		case MOS65XX_AM_SR:
			return "stack relative";
		case MOS65XX_AM_SR_IND_Y:
			return "stack relative indirect indexed with y";
	}
}


void print_insn_detail_mos65xx(csh handle, cs_insn *ins)
{
	int i;
	cs_mos65xx *mos65xx;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	mos65xx = &(ins->detail->mos65xx);
	printf("\taddress mode: %s\n", get_am_name(mos65xx->am));
	printf("\tmodifies flags: %s\n", mos65xx->modifies_flags ? "true": "false");

	if (mos65xx->op_count)
		printf("\top_count: %u\n", mos65xx->op_count);

	for (i = 0; i < mos65xx->op_count; i++) {
		cs_mos65xx_op *op = &(mos65xx->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case MOS65XX_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case MOS65XX_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case MOS65XX_OP_MEM:
				printf("\t\toperands[%u].type: MEM = 0x%x\n", i, op->mem);
				break;
		}
	}
}
