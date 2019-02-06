#include "factory.h"

char *get_detail_tms320c64x(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_tms320c64x *tms320c64x;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	tms320c64x = &(ins->detail->tms320c64x);
	if (tms320c64x->op_count)
		addStr(result, " | op_count: %u", tms320c64x->op_count);

	for (i = 0; i < tms320c64x->op_count; i++) {
		cs_tms320c64x_op *op = &(tms320c64x->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case TMS320C64X_OP_REG:
				addStr(result, " | operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case TMS320C64X_OP_IMM:
				addStr(result, " | operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case TMS320C64X_OP_MEM:
				addStr(result, " | operands[%u].type: MEM", i);
				if (op->mem.base != TMS320C64X_REG_INVALID)
					addStr(result, " | operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				addStr(result, " | operands[%u].mem.disptype: ", i);
				if(op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
					addStr(result, "Invalid");
					addStr(result, " | operands[%u].mem.disp: %u", i, op->mem.disp);
				}
				if(op->mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
					addStr(result, "Constant");
					addStr(result, " | operands[%u].mem.disp: %u", i, op->mem.disp);
				}
				if(op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
					addStr(result, "Register");
					addStr(result, " | operands[%u].mem.disp: %s", i, cs_reg_name(*handle, op->mem.disp));
				}
				addStr(result, " | operands[%u].mem.unit: %u", i, op->mem.unit);
				addStr(result, " | operands[%u].mem.direction: ", i);
				if(op->mem.direction == TMS320C64X_MEM_DIR_INVALID)
					addStr(result, "Invalid");
				if(op->mem.direction == TMS320C64X_MEM_DIR_FW)
					addStr(result, "Forward");
				if(op->mem.direction == TMS320C64X_MEM_DIR_BW)
					addStr(result, "Backward");
				addStr(result, " | operands[%u].mem.modify: ", i);
				if(op->mem.modify == TMS320C64X_MEM_MOD_INVALID)
					addStr(result, "Invalid");
				if(op->mem.modify == TMS320C64X_MEM_MOD_NO)
					addStr(result, "No");
				if(op->mem.modify == TMS320C64X_MEM_MOD_PRE)
					addStr(result, "Pre");
				if(op->mem.modify == TMS320C64X_MEM_MOD_POST)
					addStr(result, "Post");
				addStr(result, " | operands[%u].mem.scaled: %u", i, op->mem.scaled);

				break;
			case TMS320C64X_OP_REGPAIR:
				addStr(result, " | operands[%u].type: REGPAIR = %s:%s", i, cs_reg_name(*handle, op->reg + 1), cs_reg_name(*handle, op->reg));
				break;
		}
	}

	addStr(result, " | Functional unit: ");
	switch(tms320c64x->funit.unit) {
		case TMS320C64X_FUNIT_D:
			addStr(result, "D%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_L:
			addStr(result, "L%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_M:
			addStr(result, "M%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_S:
			addStr(result, "S%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_NO:
			addStr(result, "No Functional Unit");
			break;
		default:
			addStr(result, "Unknown (Unit %u, Side %u)", tms320c64x->funit.unit, tms320c64x->funit.side);
			break;
	}
	if(tms320c64x->funit.crosspath == 1)
		addStr(result, " | Crosspath: 1");

	if(tms320c64x->condition.reg != TMS320C64X_REG_INVALID)
		addStr(result, " | Condition: [%c%s]", (tms320c64x->condition.zero == 1) ? '!' : ' ', cs_reg_name(*handle, tms320c64x->condition.reg));
	addStr(result, " | Parallel: %s", (tms320c64x->parallel == 1) ? "true" : "false");

	return result;
}

