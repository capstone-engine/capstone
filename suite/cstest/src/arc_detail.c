#include "factory.h"

char *get_detail_arc(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_arc *arc;
	int i;
	char *result;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	arc = &(ins->detail->arc);
	if (arc->op_count)
		add_str(&result, " ; op_count: %u", arc->op_count);

	for (i = 0; i < arc->op_count; i++) {
		cs_arc_op *op = &(arc->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARC_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case ARC_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
		}
	}

	// Print out all registers accessed by this instruction (either implicit or
	// explicit)
	if (!cs_regs_access(*handle, ins, regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			add_str(&result, "\tRegisters read:");
			for (i = 0; i < regs_read_count; i++) {
				add_str(&result, " %s",
					cs_reg_name(*handle,
							regs_read[i]));
			}
			add_str(&result, "\n");
		}

		if (regs_write_count) {
			add_str(&result, "\tRegisters modified:");
			for (i = 0; i < regs_write_count; i++) {
				add_str(&result, " %s",
					cs_reg_name(*handle,
							regs_write[i]));
			}
			add_str(&result, "\n");
		}
	}

	return result;
}

