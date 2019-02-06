#include "factory.h" 

char *get_detail_arm(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_arm *arm;
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
		addStr(result, " | op_count: %u", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				addStr(result, " | operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case ARM_OP_IMM:
				addStr(result, " | operands[%u].type: IMM = 0x%x", i, op->imm);
				break;
			case ARM_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				addStr(result, " | operands[%u].type: FP = <float_point_unsupported>", i);
#else
				addStr(result, " | operands[%u].type: FP = %f", i, op->fp);
#endif
				break;
			case ARM_OP_MEM:
				addStr(result, " | operands[%u].type: MEM", i);
				if (op->mem.base != ARM_REG_INVALID)
					addStr(result, " | operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != ARM_REG_INVALID)
					addStr(result, " | operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.scale != 1)
					addStr(result, " | operands[%u].mem.scale: %d", i, op->mem.scale);
				if (op->mem.disp != 0)
					addStr(result, " | operands[%u].mem.disp: 0x%x", i, op->mem.disp);
				if (op->mem.lshift != 0)
					addStr(result, " | operands[%u].mem.lshift: 0x%x", i, op->mem.lshift);

				break;
			case ARM_OP_PIMM:
				addStr(result, " | operands[%u].type: P-IMM = %u", i, op->imm);
				break;
			case ARM_OP_CIMM:
				addStr(result, " | operands[%u].type: C-IMM = %u", i, op->imm);
				break;
			case ARM_OP_SETEND:
				addStr(result, " | operands[%u].type: SETEND = %s", i, op->setend == ARM_SETEND_BE? "be" : "le");
				break;
			case ARM_OP_SYSREG:
				addStr(result, " | operands[%u].type: SYSREG = %u", i, op->reg);
				break;
		}

		if (op->neon_lane != -1) {
			addStr(result, " | operands[%u].neon_lane = %u", i, op->neon_lane);
		}

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				addStr(result, " | operands[%u].access: READ", i);
				break;
			case CS_AC_WRITE:
				addStr(result, " | operands[%u].access: WRITE", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				addStr(result, " | operands[%u].access: READ | WRITE", i);
				break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				// shift with constant value
				addStr(result, " | Shift: %u = %u", op->shift.type, op->shift.value);
			else
				// shift with register
				addStr(result, " | Shift: %u = %s", op->shift.type, cs_reg_name(*handle, op->shift.value));
		}

		if (op->vector_index != -1) {
			addStr(result, " | operands[%u].vector_index = %u", i, op->vector_index);
		}

		if (op->subtracted)
			addStr(result, " | Subtracted: True");
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		addStr(result, " | Code condition: %u", arm->cc);

	if (arm->update_flags)
		addStr(result, " | Update-flags: True");

	if (arm->writeback)
		addStr(result, " | Write-back: True");

	if (arm->cps_mode)
		addStr(result, " | CPSI-mode: %u", arm->cps_mode);

	if (arm->cps_flag)
		addStr(result, " | CPSI-flag: %u", arm->cps_flag);

	if (arm->vector_data)
		addStr(result, " | Vector-data: %u", arm->vector_data);

	if (arm->vector_size)
		addStr(result, " | Vector-size: %u", arm->vector_size);

	if (arm->usermode)
		addStr(result, " | User-mode: True");

	if (arm->mem_barrier)
		addStr(result, " | Memory-barrier: %u", arm->mem_barrier);

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(*handle, ins, regs_read, &regs_read_count, regs_write, &regs_write_count)) {
		if (regs_read_count) {
			addStr(result, " | Registers read:");
			for(i = 0; i < regs_read_count; i++) {
				addStr(result, " %s", cs_reg_name(*handle, regs_read[i]));
			}
		}

		if (regs_write_count) {
			addStr(result, " | Registers modified:");
			for(i = 0; i < regs_write_count; i++) {
				addStr(result, " %s", cs_reg_name(*handle, regs_write[i]));
			}
		}
	}

	return result;
}

