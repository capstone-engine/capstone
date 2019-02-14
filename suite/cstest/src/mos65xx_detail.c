/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

static const char *get_am_name(mos65xx_address_mode mode)
{
	switch(mode) {
		default:
		case MOS65XX_AM_NONE:
			return "No address mode";
		case MOS65XX_AM_IMP:
			return "implied addressing (no addressing mode)";
		case MOS65XX_AM_ACC:
			return "accumulator addressing";
		case MOS65XX_AM_ABS:
			return "absolute addressing";
		case MOS65XX_AM_ZP:
			return "zeropage addressing";
		case MOS65XX_AM_IMM:
			return "8 Bit immediate value";
		case MOS65XX_AM_ABSX:
			return "indexed absolute addressing by the X index register";
		case MOS65XX_AM_ABSY:
			return "indexed absolute addressing by the Y index register";
		case MOS65XX_AM_INDX:
			return "indexed indirect addressing by the X index register";
		case MOS65XX_AM_INDY:
			return "indirect indexed addressing by the Y index register";
		case MOS65XX_AM_ZPX:
			return "indexed zeropage addressing by the X index register";
		case MOS65XX_AM_ZPY:
			return "indexed zeropage addressing by the Y index register";
		case MOS65XX_AM_REL:
			return "relative addressing used by branches";
		case MOS65XX_AM_IND:
			return "absolute indirect addressing";
	}
}


char *get_detail_mos65xx(csh *handle, cs_mode mode, cs_insn *ins)
{
	int i;
	cs_mos65xx *mos65xx;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	mos65xx = &(ins->detail->mos65xx);
	add_str(&result, " ; address mode: %s", get_am_name(mos65xx->am));
	add_str(&result, " ; modifies flags: %s", mos65xx->modifies_flags ? "true": "false");

	if (mos65xx->op_count)
		add_str(&result, " ; op_count: %u", mos65xx->op_count);

	for (i = 0; i < mos65xx->op_count; i++) {
		cs_mos65xx_op *op = &(mos65xx->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case MOS65XX_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case MOS65XX_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case MOS65XX_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM = 0x%x", i, op->mem);
				break;
		}
	}
	return result;
}
