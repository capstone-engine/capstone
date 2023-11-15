/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_aarch64(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_aarch64 *aarch64;
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

	aarch64 = &(ins->detail->aarch64);
	if (aarch64->op_count)
		add_str(&result, " ; op_count: %u", aarch64->op_count);

	for (i = 0; i < aarch64->op_count; i++) {
		cs_aarch64_op *op = &(aarch64->operands[i]);
		switch(op->type) {
			default:
				break;
			case AArch64_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case AArch64_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%" PRIx64, i, op->imm);
				break;
			case AArch64_OP_FP:
#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
				add_str(&result, " ; operands[%u].type: FP = <float_point_unsupported>", i);
#else
				add_str(&result, " ; operands[%u].type: FP = %f", i, op->fp);
#endif
				break;
			case AArch64_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base != AArch64_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base));
				if (op->mem.index != AArch64_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index));
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);

				break;
			case AArch64_OP_CIMM:
				add_str(&result, " ; operands[%u].type: C-IMM = %u", i, (int)op->imm);
				break;
			case AArch64_OP_REG_MRS:
				add_str(&result, " ; operands[%u].type: REG_MRS = 0x%x", i, op->reg);
				break;
			case AArch64_OP_REG_MSR:
				add_str(&result, " ; operands[%u].type: REG_MSR = 0x%x", i, op->reg);
				break;
			case AArch64_OP_SME_MATRIX:
				add_str(&result, " ; operands[%u].type: SME_MATRIX", i);
				add_str(&result, " ; operands[%u].sme.type: %d", i, op->sme.type);

				if (op->sme.tile != AArch64_REG_INVALID)
					add_str(&result, " ; operands[%u].sme.tile: %s", i, cs_reg_name(*handle, op->sme.tile));
				if (op->sme.slice_reg != AArch64_REG_INVALID)
					add_str(&result, " ; operands[%u].sme.slice_reg: %s", i, cs_reg_name(*handle, op->sme.slice_reg));
				if (op->sme.slice_offset.imm != -1 || op->sme.slice_offset.imm_range.first != -1) {
					add_str(&result, " ; operands[%u].sme.slice_offset: ", i);
					if (op->sme.has_range_offset)
						add_str(&result, "%hhd:%hhd", op->sme.slice_offset.imm_range.first, op->sme.slice_offset.imm_range.offset);
					else
						add_str(&result, "%d", op->sme.slice_offset.imm);
				}
				if (op->sme.slice_reg != AArch64_REG_INVALID || op->sme.slice_offset.imm != -1)
					add_str(&result, " ; operands[%u].sme.is_vertical: %s", i, (op->sme.is_vertical ? "true" : "false"));
				break;
		case AArch64_OP_SYSREG:
			add_str(&result, " ; operands[%u].type: SYS REG:", i);
			switch (op->sysop.sub_type) {
			default:
				break;
			case AArch64_OP_REG_MRS:
				add_str(&result, " ; operands[%u].subtype: REG_MRS = 0x%x", i, op->sysop.reg.sysreg);
				break;
			case AArch64_OP_REG_MSR:
				add_str(&result, " ; operands[%u].subtype: REG_MSR = 0x%x", i, op->sysop.reg.sysreg);
				break;
			case AArch64_OP_TLBI:
				add_str(&result, " ; operands[%u].subtype TLBI = 0x%x", i, op->sysop.reg.tlbi);
				break;
			case AArch64_OP_IC:
				add_str(&result, " ; operands[%u].subtype IC = 0x%x", i, op->sysop.reg.ic);
				break;
			}
			break;
		case AArch64_OP_SYSALIAS:
			add_str(&result, " ; operands[%u].type: SYS ALIAS:", i);
			switch (op->sysop.sub_type) {
			default:
				break;
			case AArch64_OP_SVCR:
				if(op->sysop.alias.svcr == AArch64_SVCR_SVCRSM)
					add_str(&result, " ; operands[%u].svcr: BIT = SM", i);
				else if(op->sysop.alias.svcr == AArch64_SVCR_SVCRZA)
					add_str(&result, " ; operands[%u].svcr: BIT = ZA", i);
				else if(op->sysop.alias.svcr == AArch64_SVCR_SVCRSMZA)
					add_str(&result, " ; operands[%u].svcr: BIT = SM & ZA", i);
				break;
			case AArch64_OP_AT:
				add_str(&result, " ; operands[%u].subtype AT = 0x%x", i, op->sysop.alias.at);
				break;
			case AArch64_OP_DB:
				add_str(&result, " ; operands[%u].subtype DB = 0x%x", i, op->sysop.alias.db);
				break;
			case AArch64_OP_DC:
				add_str(&result, " ; operands[%u].subtype DC = 0x%x", i, op->sysop.alias.dc);
				break;
			case AArch64_OP_ISB:
				add_str(&result, " ; operands[%u].subtype ISB = 0x%x", i, op->sysop.alias.isb);
				break;
			case AArch64_OP_TSB:
				add_str(&result, " ; operands[%u].subtype TSB = 0x%x", i, op->sysop.alias.tsb);
				break;
			case AArch64_OP_PRFM:
				add_str(&result, " ; operands[%u].subtype PRFM = 0x%x", i, op->sysop.alias.prfm);
				break;
			case AArch64_OP_SVEPRFM:
				add_str(&result, " ; operands[%u].subtype SVEPRFM = 0x%x", i, op->sysop.alias.sveprfm);
				break;
			case AArch64_OP_RPRFM:
				add_str(&result, " ; operands[%u].subtype RPRFM = 0x%x", i, op->sysop.alias.rprfm);
				break;
			case AArch64_OP_PSTATEIMM0_15:
				add_str(&result, " ; operands[%u].subtype PSTATEIMM0_15 = 0x%x", i, op->sysop.alias.pstateimm0_15);
				break;
			case AArch64_OP_PSTATEIMM0_1:
				add_str(&result, " ; operands[%u].subtype PSTATEIMM0_1 = 0x%x", i, op->sysop.alias.pstateimm0_1);
				break;
			case AArch64_OP_PSB:
				add_str(&result, " ; operands[%u].subtype PSB = 0x%x", i, op->sysop.alias.psb);
				break;
			case AArch64_OP_BTI:
				add_str(&result, " ; operands[%u].subtype BTI = 0x%x", i, op->sysop.alias.bti);
				break;
			case AArch64_OP_SVEPREDPAT:
				add_str(&result, " ; operands[%u].subtype SVEPREDPAT = 0x%x", i, op->sysop.alias.svepredpat);
				break;
			case AArch64_OP_SVEVECLENSPECIFIER:
				add_str(&result, " ; operands[%u].subtype SVEVECLENSPECIFIER = 0x%x", i, op->sysop.alias.sveveclenspecifier);
				break;
			}
			break;
		case AArch64_OP_SYSIMM:
			add_str(&result, " ; operands[%u].type: SYS IMM:", i);
			switch(op->sysop.sub_type) {
			default:
				break;
			case AArch64_OP_EXACTFPIMM:
				add_str(&result, " ; operands[%u].subtype EXACTFPIMM = %d", i, op->sysop.imm.exactfpimm);
				break;
			case AArch64_OP_DBNXS:
				add_str(&result, " ; operands[%u].subtype DBNXS = %d", i, op->sysop.imm.dbnxs);
				break;
			}
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
		
		if (op->shift.type != AArch64_SFT_INVALID &&
			op->shift.value)
			add_str(&result, " ; Shift: type = %u, value = %u",
				   op->shift.type, op->shift.value);

		if (op->ext != AArch64_EXT_INVALID)
			add_str(&result, " ; Ext: %u", op->ext);

		if (op->vas != AArch64Layout_Invalid)
			add_str(&result, " ; operands[%u].vas: 0x%x", i, op->vas);

		if (op->vector_index != -1)
			add_str(&result, " ; operands[%u].vector_index: %u", i, op->vector_index);
	}

	if (aarch64->update_flags)
		add_str(&result, " ; Update-flags: True");

	if (ins->detail->writeback)
		add_str(&result, " ; Write-back: True");

	if (aarch64->cc)
		add_str(&result, " ; Code-condition: %u", aarch64->cc);

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
