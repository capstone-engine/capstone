#include "factory.h"

char *get_detail_armmmmmmmmmmm(csh *handle, cs_insn *ins)
{
	cs_arm *arm;
	cs_arm_op *op;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	
	if (ins->detail == NULL)
		return result;

	arm = &(ins->detail->arm);
	if (arm->op_count)
		addStr(&result, " | %u", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				addStr(&result, " | %s", cs_reg_name(*handle, op->reg));
				break;
			case ARM_OP_IMM:
				addStr(&result, " | 0x%x", op->imm);
				break;
			case ARM_OP_FP:
#if defined(_KERNEL_MODE)
				addStr(&result, " | <float_point_unsupported>");
#else
				addStr(&result, " | %f", op->fp);
#endif
				break;
			case ARM_OP_MEM:
				addStr(&result, " | MEM");
				if (op->mem.base != ARM_REG_INVALID)
					addStr(&result, " | %s", cs_reg_name(*handle, op->mem.base));
				
				if (op->mem.index != ARM_REG_INVALID)
					addStr(&result, " | %s", cs_reg_name(*handle, op->mem.index));

				if (op->mem.scale != 1)
					addStr(&result, " | %d", op->mem.scale);

				if (op->mem.disp != 0)
					addStr(&result, " | 0x%x", op->mem.disp);

				if (op->mem.lshift != 0)
					addStr(&result, " | 0x%x", op->mem.lshift);
				break;
			case ARM_OP_CIMM:
			case ARM_OP_PIMM:
				addStr(&result, " | %u", op->imm);
				break;
			case ARM_OP_SETEND:
				addStr(&result, " | %s", op->setend == ARM_SETEND_BE? "be" : "le");
				break;
			case ARM_OP_SYSREG:
				addStr(&result, " | %u", op->reg);
				break;	
		}
		if (op->neon_lane != -1)
			addStr(&result, " | %u", op->neon_lane);

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				addStr(&result, " | READ");
				break;
			case CS_AC_WRITE:
				addStr(&result, " | WRITE");
				break;	
			case CS_AC_READ | CS_AC_WRITE:
				addStr(&result, " | READ WRITE");
				break;
		}
		
		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				addStr(&result, " | %u %u", op->shift.type, op->shift.value);
			else
				addStr(&result, " | %u %s", op->shift.type, cs_reg_name(*handle, op->shift.value));
		}
		
		if (op->vector_index != -1)
			addStr(&result, " | %u", op->vector_index);

		if (op->subtracted)
			addStr(&result, " | True");
	}
	return result;
}
