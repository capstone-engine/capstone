/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "capstone/aarch64.h"
#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_aarch64(csh handle, cs_insn *ins)
{
	cs_aarch64 *aarch64;
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	uint8_t access;
	
	// detail can be NULL if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	aarch64 = &(ins->detail->aarch64);
	if (aarch64->op_count)
		printf("\top_count: %u\n", aarch64->op_count);

	for (i = 0; i < aarch64->op_count; i++) {
		cs_aarch64_op *op = &(aarch64->operands[i]);
		switch(op->type) {
		default:
			printf("\t\tOperand type %" PRId32 " not handled\n", op->type);
			break;
		case AARCH64_OP_REG:
			printf("\t\toperands[%u].type: REG = %s%s\n", i, cs_reg_name(handle, op->reg), op->is_vreg ? " (vreg)" : "");
			if (op->is_list_member) {
				printf("\t\toperands[%u].is_list_member: true\n", i);
			}
			break;
		case AARCH64_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
			break;
		case AARCH64_OP_FP:
#if defined(_KERNEL_MODE)
			// Issue #681: Windows kernel does not support formatting float point
			printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
			printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
#endif
			break;
		case AARCH64_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != AARCH64_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != AARCH64_REG_INVALID)
				printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
			if (ins->detail->aarch64.post_index)
				printf("\t\t\tpost-indexed: true\n");

			break;
		case AARCH64_OP_SME:
			printf("\t\toperands[%u].type: SME_MATRIX\n", i);
			printf("\t\toperands[%u].sme.type: %d\n", i, op->sme.type);

			if (op->sme.tile != AARCH64_REG_INVALID)
				printf("\t\toperands[%u].sme.tile: %s\n", i, cs_reg_name(handle, op->sme.tile));
			if (op->sme.slice_reg != AARCH64_REG_INVALID)
				printf("\t\toperands[%u].sme.slice_reg: %s\n", i, cs_reg_name(handle, op->sme.slice_reg));
			if (op->sme.slice_offset.imm != AARCH64_SLICE_IMM_INVALID || op->sme.slice_offset.imm_range.first != AARCH64_SLICE_IMM_RANGE_INVALID) {
				printf("\t\toperands[%u].sme.slice_offset: ", i);
				if (op->sme.has_range_offset)
					printf("%hhd:%hhd\n", op->sme.slice_offset.imm_range.first, op->sme.slice_offset.imm_range.offset);
				else
					printf("%d\n", op->sme.slice_offset.imm);
			}
			if (op->sme.slice_reg != AARCH64_REG_INVALID || op->sme.slice_offset.imm != AARCH64_SLICE_IMM_INVALID)
				printf("\t\toperands[%u].sme.is_vertical: %s\n", i, (op->sme.is_vertical ? "true" : "false"));
			break;
		case AARCH64_OP_PRED:
			printf("\t\toperands[%u].type: PREDICATE\n", i);
			if (op->pred.reg != AARCH64_REG_INVALID)
				printf("\t\toperands[%u].pred.reg: %s\n", i, cs_reg_name(handle, op->pred.reg));
			if (op->pred.vec_select != AARCH64_REG_INVALID)
				printf("\t\toperands[%u].pred.vec_select: %s\n", i, cs_reg_name(handle, op->pred.vec_select));
			if (op->pred.imm_index != -1)
				printf("\t\toperands[%u].pred.imm_index: %d\n", i, op->pred.imm_index);
			break;
		case AARCH64_OP_CIMM:
			printf("\t\toperands[%u].type: C-IMM = %u\n", i, (int)op->imm);
			break;
		case AARCH64_OP_SYSREG:
			printf("\t\toperands[%u].type: SYS REG:\n", i);
			switch (op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AARCH64_OP_REG_MRS:
				printf("\t\toperands[%u].subtype: REG_MRS = 0x%x\n", i, op->sysop.reg.sysreg);
				break;
			case AARCH64_OP_REG_MSR:
				printf("\t\toperands[%u].subtype: REG_MSR = 0x%x\n", i, op->sysop.reg.sysreg);
				break;
			case AARCH64_OP_TLBI:
				printf("\t\toperands[%u].subtype TLBI = 0x%x\n", i, op->sysop.reg.tlbi);
				break;
			case AARCH64_OP_IC:
				printf("\t\toperands[%u].subtype IC = 0x%x\n", i, op->sysop.reg.ic);
				break;
			}
			break;
		case AARCH64_OP_SYSALIAS:
			printf("\t\toperands[%u].type: SYS ALIAS:\n", i);
			switch (op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AARCH64_OP_SVCR:
				if(op->sysop.alias.svcr == AARCH64_SVCR_SVCRSM)
					printf("\t\t\toperands[%u].svcr: BIT = SM\n", i);
				else if(op->sysop.alias.svcr == AARCH64_SVCR_SVCRZA)
					printf("\t\t\toperands[%u].svcr: BIT = ZA\n", i);
				else if(op->sysop.alias.svcr == AARCH64_SVCR_SVCRSMZA)
					printf("\t\t\toperands[%u].svcr: BIT = SM & ZA\n", i);
				break;
			case AARCH64_OP_AT:
				printf("\t\toperands[%u].subtype AT = 0x%x\n", i, op->sysop.alias.at);
				break;
			case AARCH64_OP_DB:
				printf("\t\toperands[%u].subtype DB = 0x%x\n", i, op->sysop.alias.db);
				break;
			case AARCH64_OP_DC:
				printf("\t\toperands[%u].subtype DC = 0x%x\n", i, op->sysop.alias.dc);
				break;
			case AARCH64_OP_ISB:
				printf("\t\toperands[%u].subtype ISB = 0x%x\n", i, op->sysop.alias.isb);
				break;
			case AARCH64_OP_TSB:
				printf("\t\toperands[%u].subtype TSB = 0x%x\n", i, op->sysop.alias.tsb);
				break;
			case AARCH64_OP_PRFM:
				printf("\t\toperands[%u].subtype PRFM = 0x%x\n", i, op->sysop.alias.prfm);
				break;
			case AARCH64_OP_SVEPRFM:
				printf("\t\toperands[%u].subtype SVEPRFM = 0x%x\n", i, op->sysop.alias.sveprfm);
				break;
			case AARCH64_OP_RPRFM:
				printf("\t\toperands[%u].subtype RPRFM = 0x%x\n", i, op->sysop.alias.rprfm);
				break;
			case AARCH64_OP_PSTATEIMM0_15:
				printf("\t\toperands[%u].subtype PSTATEIMM0_15 = 0x%x\n", i, op->sysop.alias.pstateimm0_15);
				break;
			case AARCH64_OP_PSTATEIMM0_1:
				printf("\t\toperands[%u].subtype PSTATEIMM0_1 = 0x%x\n", i, op->sysop.alias.pstateimm0_1);
				break;
			case AARCH64_OP_PSB:
				printf("\t\toperands[%u].subtype PSB = 0x%x\n", i, op->sysop.alias.psb);
				break;
			case AARCH64_OP_BTI:
				printf("\t\toperands[%u].subtype BTI = 0x%x\n", i, op->sysop.alias.bti);
				break;
			case AARCH64_OP_SVEPREDPAT:
				printf("\t\toperands[%u].subtype SVEPREDPAT = 0x%x\n", i, op->sysop.alias.svepredpat);
				break;
			case AARCH64_OP_SVEVECLENSPECIFIER:
				printf("\t\toperands[%u].subtype SVEVECLENSPECIFIER = 0x%x\n", i, op->sysop.alias.sveveclenspecifier);
				break;
			}
			break;
		case AARCH64_OP_SYSIMM:
			printf("\t\toperands[%u].type: SYS IMM:\n", i);
			switch(op->sysop.sub_type) {
			default:
				printf("Sub type %d not handled.\n", op->sysop.sub_type);
				break;
			case AARCH64_OP_EXACTFPIMM:
				printf("\t\toperands[%u].subtype EXACTFPIMM = %d\n", i, op->sysop.imm.exactfpimm);
				printf("\t\toperands[%u].fp = %.1f\n", i, op->fp);
				break;
			case AARCH64_OP_DBNXS:
				printf("\t\toperands[%u].subtype DBNXS = %d\n", i, op->sysop.imm.dbnxs);
				break;
			}
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
		
		if (op->shift.type != AARCH64_SFT_INVALID &&
			op->shift.value)
			printf("\t\t\tShift: type = %u, value = %u\n",
				   op->shift.type, op->shift.value);

		if (op->ext != AARCH64_EXT_INVALID)
			printf("\t\t\tExt: %u\n", op->ext);

		if (op->vas != AARCH64LAYOUT_INVALID)
			printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op->vas);

		if (op->vector_index != -1)
			printf("\t\t\tVector Index: %u\n", op->vector_index);
	}

	if (aarch64->update_flags)
		printf("\tUpdate-flags: True\n");

	if (ins->detail->writeback)
		printf("\tWrite-back: True\n");

	if (aarch64->cc != AArch64CC_Invalid)
		printf("\tCode-condition: %u\n", aarch64->cc);

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
