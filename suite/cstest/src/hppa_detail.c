/* Capstone testing regression */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#include "factory.h"

char *get_detail_hppa(csh *p_handle, cs_mode mode, cs_insn *ins)
{
	cs_hppa *hppa;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	char *result;
	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	csh handle = *p_handle;

	hppa = &(ins->detail->hppa);

	if (hppa->op_count)
		add_str(&result, "\top_count: %u\n", hppa->op_count);

	for (i = 0; i < hppa->op_count; i++) {
		cs_hppa_op *op = &(hppa->operands[i]);
		switch ((int)op->type) {
		default:
			break;
		case HPPA_OP_REG:
			add_str(&result, "\t\toperands[%u].type: REG = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;
		case HPPA_OP_IMM:
			add_str(&result, "\t\toperands[%u].type: IMM = 0x%x\n",
				i, op->imm);
			break;
		case HPPA_OP_IDX_REG:
			add_str(&result,
				"\t\toperands[%u].type: IDX_REG = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;
		case HPPA_OP_DISP:
			add_str(&result, "\t\toperands[%u].type: DISP = 0x%x\n",
				i, op->imm);
			break;
		case HPPA_OP_MEM:
			add_str(&result, "\t\toperands[%u].type:  MEM\n", i);
			if (op->mem.space != HPPA_REG_INVALID) {
				add_str(&result,
					"\t\t\toperands[%u].mem.space: REG = %s\n",
					i, cs_reg_name(handle, op->mem.space));
			}
			add_str(&result,
				"\t\t\toperands[%u].mem.base: REG = %s\n", i,
				cs_reg_name(handle, op->mem.base));
			break;
		case HPPA_OP_TARGET:
			add_str(&result, "\t\toperands[%u].type: ", i);
			if (op->imm >= 0x8000000000000000)
				add_str(&result, "TARGET = -0x%lx\n", -op->imm);
			else
				add_str(&result, "TARGET = 0x%lx\n", op->imm);
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
