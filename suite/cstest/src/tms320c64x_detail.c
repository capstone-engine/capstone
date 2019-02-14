/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_tms320c64x(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_tms320c64x *tms320c64x;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	tms320c64x = &(ins->detail->tms320c64x);
	if (tms320c64x->op_count)
		add_str(&result, " ; op_count: %u", tms320c64x->op_count);

	for (i = 0; i < tms320c64x->op_count; i++) {
		cs_tms320c64x_op *op = &(tms320c64x->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case TMS320C64X_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case TMS320C64X_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case TMS320C64X_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != TMS320C64X_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				add_str(&result, " ; operands[%u].mem.disptype: ", i);
				if (op->mem.disptype == TMS320C64X_MEM_DISP_INVALID) {
					add_str(&result, "Invalid");
					add_str(&result, " ; operands[%u].mem.disp: %u", i, op->mem.disp);
				}
				if (op->mem.disptype == TMS320C64X_MEM_DISP_CONSTANT) {
					add_str(&result, "Constant");
					add_str(&result, " ; operands[%u].mem.disp: %u", i, op->mem.disp);
				}
				if (op->mem.disptype == TMS320C64X_MEM_DISP_REGISTER) {
					add_str(&result, "Register");
					add_str(&result, " ; operands[%u].mem.disp: %s", i, cs_reg_name(*handle, op->mem.disp));
				}
				add_str(&result, " ; operands[%u].mem.unit: %u", i, op->mem.unit);
				add_str(&result, " ; operands[%u].mem.direction: ", i);
				if (op->mem.direction == TMS320C64X_MEM_DIR_INVALID)
					add_str(&result, "Invalid");
				if (op->mem.direction == TMS320C64X_MEM_DIR_FW)
					add_str(&result, "Forward");
				if (op->mem.direction == TMS320C64X_MEM_DIR_BW)
					add_str(&result, "Backward");
				add_str(&result, " ; operands[%u].mem.modify: ", i);
				if (op->mem.modify == TMS320C64X_MEM_MOD_INVALID)
					add_str(&result, "Invalid");
				if (op->mem.modify == TMS320C64X_MEM_MOD_NO)
					add_str(&result, "No");
				if (op->mem.modify == TMS320C64X_MEM_MOD_PRE)
					add_str(&result, "Pre");
				if (op->mem.modify == TMS320C64X_MEM_MOD_POST)
					add_str(&result, "Post");
				add_str(&result, " ; operands[%u].mem.scaled: %u", i, op->mem.scaled);

				break;
			case TMS320C64X_OP_REGPAIR:
				add_str(&result, " ; operands[%u].type: REGPAIR = %s:%s", i, cs_reg_name(*handle, op->reg + 1), cs_reg_name(*handle, op->reg));
				break;
		}
	}

	add_str(&result, " ; Functional unit: ");
	switch(tms320c64x->funit.unit) {
		case TMS320C64X_FUNIT_D:
			add_str(&result, "D%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_L:
			add_str(&result, "L%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_M:
			add_str(&result, "M%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_S:
			add_str(&result, "S%u", tms320c64x->funit.side);
			break;
		case TMS320C64X_FUNIT_NO:
			add_str(&result, "No Functional Unit");
			break;
		default:
			add_str(&result, "Unknown (Unit %u, Side %u)", tms320c64x->funit.unit, tms320c64x->funit.side);
			break;
	}
	if (tms320c64x->funit.crosspath == 1)
		add_str(&result, " ; Crosspath: 1");

	if (tms320c64x->condition.reg != TMS320C64X_REG_INVALID)
		add_str(&result, " ; Condition: [%c%s]", (tms320c64x->condition.zero == 1) ? '!' : ' ', cs_reg_name(*handle, tms320c64x->condition.reg));
	add_str(&result, " ; Parallel: %s", (tms320c64x->parallel == 1) ? "true" : "false");

	return result;
}

