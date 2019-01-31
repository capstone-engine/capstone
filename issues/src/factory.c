#include "factory.h"

char *get_detail_arm(csh *handle, cs_insn *ins)
{
	cs_arm *arm;
	cs_arm_op *op;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	char *result, *tmp;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	tmp = (char *)malloc(sizeof(char) * 100);
	
	if (ins->detail == NULL)
		return result;

	arm = &(ins->detail->arm);
	if (arm->op_count) {
		sprintf(tmp, " | %u", arm->op_count);	
		addStr(result, tmp);
	}

	for (i = 0; i < arm->op_count; i++) {
		op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				sprintf(tmp, " | %s", cs_reg_name(handle, op->reg));
				addStr(result, tmp);
				break;
			case ARM_OP_IMM:
				sprintf(tmp, " | 0x%x", op->imm);
				addStr(result, tmp);
				break;
			case ARM_OP_FP:
#if defined(_KERNEL_MODE)
				sprintf(tmp, " | <float_point_unsupported>");
#else
				sprintf(tmp, " | %f", op->fp);
#endif
				addStr(result, tmp);
				break;
			case ARM_OP_MEM:
				sprintf(tmp, " | MEM");
				addStr(result, tmp);
				if (op->mem.base != ARM_REG_INVALID) {
					sprintf(tmp, " | %s", cs_reg_name(*handle, op->mem.base));
					addStr(result, tmp);
				}
				
				if (op->mem.index != ARM_REG_INVALID) {
					sprintf(tmp, " | %s", cs_reg_name(*handle, op->mem.index));
					addStr(result, tmp);
				}

				if (op->mem.scale != 1) {
					sprintf(tmp, " | %d", op->mem.scale);
					addStr(result, tmp);
				}

				if (op->mem.disp != 0) {
					sprintf(tmp, " | 0x%x", op->mem.disp);
					addStr(result, tmp);
				}

				if (op->mem.lshift != 0) {
					sprintf(tmp, " | 0x%x", op->mem.lshift);
					addStr(result, tmp);
				}

				break;
			case ARM_OP_CIMM:
			case ARM_OP_PIMM:
				sprintf(tmp, " | %u", op->imm);
				addStr(result, tmp);
				break;
			case ARM_OP_SETEND:
				sprintf(tmp, " | %s", op->setend == ARM_SETEND_BE? "be" : "le");
				addStr(result, tmp);
				break;
			case ARM_OP_SYSREG:
				sprintf(tmp, " | %u", op->reg);
				addStr(result, tmp);
				break;	
		}
	}
}
