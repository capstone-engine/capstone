/* Capstone testing regression */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#include "factory.h"

char *get_detail_alpha(csh *p_handle, cs_mode mode, cs_insn *ins)
{
	cs_alpha *alpha;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	char *result;
	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	csh handle = *p_handle;

	alpha = &(ins->detail->alpha);

	if (alpha->op_count)
		add_str(&result, "\top_count: %u\n", alpha->op_count);

	for (i = 0; i < alpha->op_count; i++) {
		cs_alpha_op *op = &(alpha->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case ALPHA_OP_REG:
			add_str(&result, "\t\toperands[%u].type: REG = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;
		case ALPHA_OP_IMM:
			add_str(&result, "\t\toperands[%u].type: IMM = 0x%x\n",
				i, op->imm);
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
