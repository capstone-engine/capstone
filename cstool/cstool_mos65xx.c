#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

void print_string_hex(char *comment, unsigned char *str, size_t len);

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
