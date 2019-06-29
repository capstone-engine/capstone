/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_arm64(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_arm64 *arm64;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	uint8_t access;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	// detail can be NULL if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	arm64 = &(ins->detail->arm64);
	if (arm64->op_count)
		add_str(&result, " ; op_count: %u", arm64->op_count);

	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &(arm64->operands[i]);
		switch(op->type) {
			default:
				break;
			case ARM64_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case ARM64_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%" PRIx64, i, op->imm);
				break;
			case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				add_str(&result, " ; operands[%u].type: FP = <float_point_unsupported>", i);
#else
				add_str(&result, " ; operands[%u].type: FP = %f", i, op->fp);
#endif
				break;
			case ARM64_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != ARM64_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != ARM64_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);

				break;
			case ARM64_OP_CIMM:
				add_str(&result, " ; operands[%u].type: C-IMM = %u", i, (int)op->imm);
				break;
			case ARM64_OP_REG_MRS:
				add_str(&result, " ; operands[%u].type: REG_MRS = 0x%x", i, op->reg);
				break;
			case ARM64_OP_REG_MSR:
				add_str(&result, " ; operands[%u].type: REG_MSR = 0x%x", i, op->reg);
				break;
			case ARM64_OP_PSTATE:
				add_str(&result, " ; operands[%u].type: PSTATE = 0x%x", i, op->pstate);
				break;
			case ARM64_OP_SYS:
				add_str(&result, " ; operands[%u].type: SYS = 0x%x", i, op->sys);
				break;
			case ARM64_OP_PREFETCH:
				add_str(&result, " ; operands[%u].type: PREFETCH = 0x%x", i, op->prefetch);
				break;
			case ARM64_OP_BARRIER:
				add_str(&result, " ; operands[%u].type: BARRIER = 0x%x", i, op->barrier);
				break;
		}
		
		access = op->access;
		switch(access) {
			default:
				break;
			case CS_AC_READ:
				add_str(&result, " ; operands[%u].access: READ", i);
				break;
			case CS_AC_WRITE:
				add_str(&result, " ; operands[%u].access: WRITE", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				add_str(&result, " ; operands[%u].access: READ | WRITE", i);
				break;
		}
		
		if (op->shift.type != ARM64_SFT_INVALID &&
			op->shift.value)
			add_str(&result, " ; Shift: type = %u, value = %u",
				   op->shift.type, op->shift.value);

		if (op->ext != ARM64_EXT_INVALID)
			add_str(&result, " ; Ext: %u", op->ext);

		if (op->vas != ARM64_VAS_INVALID)
			add_str(&result, " ; Vector Arrangement Specifier: 0x%x", op->vas);

		if (op->vector_index != -1)
			add_str(&result, " ; Vector Index: %u", op->vector_index);
	}

	if (arm64->update_flags)
		add_str(&result, " ; Update-flags: True");

	if (arm64->writeback)
		add_str(&result, " ; Write-back: True");

	if (arm64->cc)
		add_str(&result, " ; Code-condition: %u", arm64->cc);

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(*handle, ins,
						regs_read, &regs_read_count,
						regs_write, &regs_write_count)) {
		if (regs_read_count) {
			add_str(&result, " ; Registers read:");
			for(i = 0; i < regs_read_count; i++) {
				add_str(&result, " %s", cs_reg_name(*handle, regs_read[i]));
			}
		}
		
		if (regs_write_count) {
			add_str(&result, " ; Registers modified:");
			for(i = 0; i < regs_write_count; i++) {
				add_str(&result, " %s", cs_reg_name(*handle, regs_write[i]));
			}
		}
	}

	return result;
}
