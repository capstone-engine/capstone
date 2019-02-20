#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

void print_insn_detail_arm(csh handle, cs_insn *ins);

void print_insn_detail_arm(csh handle, cs_insn *ins)
{
	cs_arm *arm;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm = &(ins->detail->arm);

	if (arm->op_count)
		printf("\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case ARM_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case ARM_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
				break;
			case ARM_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != ARM_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != ARM_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %d\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
				if (op->mem.lshift != 0)
					printf("\t\t\toperands[%u].mem.lshift: 0x%x\n", i, op->mem.lshift);

				break;
			case ARM_OP_PIMM:
				printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_CIMM:
				printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_SETEND:
				printf("\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE? "be" : "le");
				break;
			case ARM_OP_SYSREG:
				printf("\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
				break;
		}

		if (op->neon_lane != -1) {
			printf("\t\toperands[%u].neon_lane = %u\n", i, op->neon_lane);
		}

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG)
				// shift with constant value
				printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			else
				// shift with register
				printf("\t\t\tShift: %u = %s\n", op->shift.type,
						cs_reg_name(handle, op->shift.value));
		}

		if (op->vector_index != -1) {
			printf("\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
		}

		if (op->subtracted)
			printf("\t\tSubtracted: True\n");
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		printf("\tCode condition: %u\n", arm->cc);

	if (arm->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm->writeback)
		printf("\tWrite-back: True\n");

	if (arm->cps_mode)
		printf("\tCPSI-mode: %u\n", arm->cps_mode);

	if (arm->cps_flag)
		printf("\tCPSI-flag: %u\n", arm->cps_flag);

	if (arm->vector_data)
		printf("\tVector-data: %u\n", arm->vector_data);

	if (arm->vector_size)
		printf("\tVector-size: %u\n", arm->vector_size);

	if (arm->usermode)
		printf("\tUser-mode: True\n");

	if (arm->mem_barrier)
		printf("\tMemory-barrier: %u\n", arm->mem_barrier);

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(handle, ins,
				regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}
}
