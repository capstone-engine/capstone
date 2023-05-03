//
// Created by aya on 3/24/23.
//

#include "factory.h"

char *get_detail_tricore(csh *p_handle, cs_mode mode, cs_insn *ins)
{
	cs_tricore *tricore;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	char *result;
	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	csh handle = *p_handle;

	tricore = &(ins->detail->tricore);

	if (tricore->op_count)
		add_str(&result, "\top_count: %u\n", tricore->op_count);

	for (i = 0; i < tricore->op_count; i++) {
		cs_tricore_op *op = &(tricore->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case TRICORE_OP_REG:
			add_str(&result, "\t\toperands[%u].type: REG = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;
		case TRICORE_OP_IMM:
			add_str(&result, "\t\toperands[%u].type: IMM = 0x%x\n",
				i, op->imm);
			break;
		case TRICORE_OP_MEM:
			add_str(&result, "\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != TRICORE_REG_INVALID)
				add_str(&result,
					"\t\t\toperands[%u].mem.base: REG = %s\n",
					i, cs_reg_name(handle, op->mem.base));
			if (op->mem.disp != 0)
				add_str(&result,
					"\t\t\toperands[%u].mem.disp: 0x%x\n",
					i, op->mem.disp);
			break;
		}

		// Print out all registers accessed by this instruction (either implicit or
		// explicit)
		if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
				    regs_write, &regs_write_count)) {
			if (regs_read_count) {
				add_str(&result, "\tRegisters read:");
				for (i = 0; i < regs_read_count; i++) {
					add_str(&result, " %s",
						cs_reg_name(handle,
							    regs_read[i]));
				}
				add_str(&result, "\n");
			}

			if (regs_write_count) {
				add_str(&result, "\tRegisters modified:");
				for (i = 0; i < regs_write_count; i++) {
					add_str(&result, " %s",
						cs_reg_name(handle,
							    regs_write[i]));
				}
				add_str(&result, "\n");
			}
		}
	}

	return result;
}
