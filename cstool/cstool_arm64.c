/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <capstone.h>

void print_string_hex(char *comment, unsigned char *str, size_t len);

void print_insn_detail_arm64(csh handle, cs_insn *ins)
{
	cs_arm64 *arm64;
	int i;

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
		}

		if (op->shift.type != ARM64_SFT_INVALID &&
				op->shift.value)
			printf("\t\t\tShift: type = %u, value = %u\n",
					op->shift.type, op->shift.value);

		if (op->ext != ARM64_EXT_INVALID)
			printf("\t\t\tExt: %u\n", op->ext);

		if (op->vas != ARM64_VAS_INVALID)
			printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op->vas);

		if (op->vess != ARM64_VESS_INVALID)
			printf("\t\t\tVector Element Size Specifier: %u\n", op->vess);

		if (op->vector_index != -1)
			printf("\t\t\tVector Index: %u\n", op->vector_index);
	}

	if (arm64->update_flags)
		printf("\tUpdate-flags: True\n");

	if (arm64->writeback)
		printf("\tWrite-back: True\n");

	if (arm64->cc)
		printf("\tCode-condition: %u\n", arm64->cc);
}
