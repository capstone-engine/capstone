/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_arm64(csh handle, cs_insn *ins)
{
	cs_arm64 *arm64;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	uint8_t access;
	
	// detail can be NULL if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm64 = &(ins->detail->arm64);
	if (arm64->op_count)
		printf("\top_count: %u\n", arm64->op_count);

	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &(arm64->operands[i]);
		switch(op->type) {
			default:
				break;
			case ARM64_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case ARM64_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
				printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
				break;
			case ARM64_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != ARM64_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != ARM64_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case ARM64_OP_CIMM:
				printf("\t\toperands[%u].type: C-IMM = %u\n", i, (int)op->imm);
				break;
			case ARM64_OP_REG_MRS:
				printf("\t\toperands[%u].type: REG_MRS = 0x%x\n", i, op->reg);
				break;
			case ARM64_OP_REG_MSR:
				printf("\t\toperands[%u].type: REG_MSR = 0x%x\n", i, op->reg);
				break;
			case ARM64_OP_PSTATE:
				printf("\t\toperands[%u].type: PSTATE = 0x%x\n", i, op->pstate);
				break;
			case ARM64_OP_SYS:
				printf("\t\toperands[%u].type: SYS = 0x%x\n", i, op->sys);
				break;
			case ARM64_OP_PREFETCH:
				printf("\t\toperands[%u].type: PREFETCH = 0x%x\n", i, op->prefetch);
				break;
			case ARM64_OP_BARRIER:
				printf("\t\toperands[%u].type: BARRIER = 0x%x\n", i, op->barrier);
				break;
			case ARM64_OP_SVCR:
				printf("\t\toperands[%u].type: SYS = 0x%x\n", i, op->sys);
				if(op->svcr == ARM64_SVCR_SVCRSM)
					printf("\t\t\toperands[%u].svcr: BIT = SM\n", i);
				if(op->svcr == ARM64_SVCR_SVCRZA)
					printf("\t\t\toperands[%u].svcr: BIT = ZA\n", i);
				if(op->svcr == ARM64_SVCR_SVCRSMZA)
					printf("\t\t\toperands[%u].svcr: BIT = SM & ZA\n", i);
				break;
			case ARM64_OP_SME_INDEX:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->sme_index.reg));
				if (op->sme_index.base != ARM64_REG_INVALID)
					printf("\t\t\toperands[%u].index.base: REG = %s\n", i, cs_reg_name(handle, op->sme_index.base));
				if (op->sme_index.disp != 0)
					printf("\t\t\toperands[%u].index.disp: 0x%x\n", i, op->sme_index.disp);
				break;
		}
		
		access = op->access;
		switch(access) {
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
		
		if (op->shift.type != ARM64_SFT_INVALID &&
			op->shift.value)
			printf("\t\t\tShift: type = %u, value = %u\n",
				   op->shift.type, op->shift.value);

		if (op->ext != ARM64_EXT_INVALID)
			printf("\t\t\tExt: %u\n", op->ext);

		if (op->vas != ARM64_VAS_INVALID)
			printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op->vas);

		if (op->vector_index != -1)
			printf("\t\t\tVector Index: %u\n", op->vector_index);
	}

	if (arm64->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm64->writeback)
		printf("\tWrite-back: True\n");

	if (arm64->cc)
		printf("\tCode-condition: %u\n", arm64->cc);

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
