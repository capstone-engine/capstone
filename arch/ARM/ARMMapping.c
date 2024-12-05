/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifdef CAPSTONE_HAS_ARM

#include <stdio.h>
#include <string.h>

#include "capstone/arm.h"
#include "capstone/capstone.h"

#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../cs_priv.h"
#include "../../cs_simple_types.h"

#include "ARMAddressingModes.h"
#include "ARMDisassemblerExtension.h"
#include "ARMBaseInfo.h"
#include "ARMLinkage.h"
#include "ARMInstPrinter.h"
#include "ARMMapping.h"

static const name_map insn_alias_mnem_map[] = {
	#include "ARMGenCSAliasMnemMap.inc"
	{ ARM_INS_ALIAS_ASR, "asr" },
	{ ARM_INS_ALIAS_LSL, "lsl" },
	{ ARM_INS_ALIAS_LSR, "lsr" },
	{ ARM_INS_ALIAS_ROR, "ror" },
	{ ARM_INS_ALIAS_RRX, "rrx" },
	{ ARM_INS_ALIAS_UXTW, "uxtw" },
	{ ARM_INS_ALIAS_LDM, "ldm" },
	{ ARM_INS_ALIAS_POP, "pop" },
	{ ARM_INS_ALIAS_PUSH, "push" },
	{ ARM_INS_ALIAS_POPW, "pop.w" },
	{ ARM_INS_ALIAS_PUSHW, "push.w" },
	{ ARM_INS_ALIAS_VPOP, "vpop" },
	{ ARM_INS_ALIAS_VPUSH, "vpush" },
	{ ARM_INS_ALIAS_END, NULL }
};

static const char *get_custom_reg_alias(unsigned reg)
{
	switch (reg) {
	case ARM_REG_R9:
		return "sb";
	case ARM_REG_R10:
		return "sl";
	case ARM_REG_R11:
		return "fp";
	case ARM_REG_R12:
		return "ip";
	case ARM_REG_R13:
		return "sp";
	case ARM_REG_R14:
		return "lr";
	case ARM_REG_R15:
		return "pc";
	}
	return NULL;
}

const char *ARM_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;
	const char *alias = get_custom_reg_alias(reg);
	if ((syntax_opt & CS_OPT_SYNTAX_CS_REG_ALIAS) && alias)
		return alias;

	if (reg == ARM_REG_INVALID || reg >= ARM_REG_ENDING) {
		// This might be a system register or banked register encoding.
		// Note: The system and banked register encodings can overlap.
		// So this might return a system register name although a
		// banked register name is expected.
		const ARMSysReg_MClassSysReg *sys_reg =
			ARMSysReg_lookupMClassSysRegByEncoding(reg);
		if (sys_reg)
			return sys_reg->Name;
		const ARMBankedReg_BankedReg *banked_reg =
			ARMBankedReg_lookupBankedRegByEncoding(reg);
		if (banked_reg)
			return banked_reg->Name;
	}

	if (syntax_opt & CS_OPT_SYNTAX_NOREGNAME) {
		return ARM_LLVM_getRegisterName(reg, ARM_NoRegAltName);
	}
	return ARM_LLVM_getRegisterName(reg, ARM_RegNamesRaw);
}

const insn_map arm_insns[] = {
#include "ARMGenCSMappingInsn.inc"
};

void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by ARM. Information is set after disassembly.
}

/// Patches the register names with Capstone specific alias.
/// Those are common alias for registers (e.g. r15 = pc)
/// which are not set in LLVM.
static void patch_cs_reg_alias(char *asm_str)
{
	char *r9 = strstr(asm_str, "r9");
	while (r9) {
		r9[0] = 's';
		r9[1] = 'b';
		r9 = strstr(asm_str, "r9");
	}
	char *r10 = strstr(asm_str, "r10");
	while (r10) {
		r10[0] = 's';
		r10[1] = 'l';
		memmove(r10 + 2, r10 + 3, strlen(r10 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r10 = strstr(asm_str, "r10");
	}
	char *r11 = strstr(asm_str, "r11");
	while (r11) {
		r11[0] = 'f';
		r11[1] = 'p';
		memmove(r11 + 2, r11 + 3, strlen(r11 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r11 = strstr(asm_str, "r11");
	}
	char *r12 = strstr(asm_str, "r12");
	while (r12) {
		r12[0] = 'i';
		r12[1] = 'p';
		memmove(r12 + 2, r12 + 3, strlen(r12 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r12 = strstr(asm_str, "r12");
	}
	char *r13 = strstr(asm_str, "r13");
	while (r13) {
		r13[0] = 's';
		r13[1] = 'p';
		memmove(r13 + 2, r13 + 3, strlen(r13 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r13 = strstr(asm_str, "r13");
	}
	char *r14 = strstr(asm_str, "r14");
	while (r14) {
		r14[0] = 'l';
		r14[1] = 'r';
		memmove(r14 + 2, r14 + 3, strlen(r14 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r14 = strstr(asm_str, "r14");
	}
	char *r15 = strstr(asm_str, "r15");
	while (r15) {
		r15[0] = 'p';
		r15[1] = 'c';
		memmove(r15 + 2, r15 + 3, strlen(r15 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		r15 = strstr(asm_str, "r15");
	}
}

/// Check if PC is updated from stack. Those POP instructions
/// are considered of group RETURN.
static void check_pop_return(MCInst *MI) {
	if (!MI->flat_insn->detail)
		return;
	if (MI->flat_insn->id != ARM_INS_POP && MI->flat_insn->alias_id != ARM_INS_ALIAS_POP) {
		return;
	}
	for (size_t i = 0; i < ARM_get_detail(MI)->op_count; ++i) {
		cs_arm_op *op = &ARM_get_detail(MI)->operands[i];
		if (op->type == ARM_OP_REG && op->reg == ARM_REG_PC) {
			add_group(MI, ARM_GRP_RET);
			return;
		}
	}
}

/// Check if PC is directly written.Those instructions
/// are considered of group BRANCH.
static void check_writes_to_pc(MCInst *MI) {
	if (!MI->flat_insn->detail)
		return;
	for (size_t i = 0; i < ARM_get_detail(MI)->op_count; ++i) {
		cs_arm_op *op = &ARM_get_detail(MI)->operands[i];
		if (op->type == ARM_OP_REG && op->reg == ARM_REG_PC && (op->access & CS_AC_WRITE)) {
			add_group(MI, ARM_GRP_JUMP);
			return;
		}
	}
}

/// Adds group to the instruction which are not defined in LLVM.
static void ARM_add_cs_groups(MCInst *MI)
{
	if (!MI->flat_insn->detail)
		return;
	check_pop_return(MI);
	check_writes_to_pc(MI);
	unsigned Opcode = MI->flat_insn->id;
	switch (Opcode) {
	default:
		return;
	case ARM_INS_SVC:
		add_group(MI, ARM_GRP_INT);
		break;
	case ARM_INS_CDP:
	case ARM_INS_CDP2:
	case ARM_INS_MCR:
	case ARM_INS_MCR2:
	case ARM_INS_MCRR:
	case ARM_INS_MCRR2:
	case ARM_INS_MRC:
	case ARM_INS_MRC2:
	case ARM_INS_SMC:
		add_group(MI, ARM_GRP_PRIVILEGE);
		break;
	}
}

static void add_alias_details(MCInst *MI) {
	if (!detail_is_set(MI))
		return;
	switch (MI->flat_insn->alias_id) {
	default:
		return;
	case ARM_INS_ALIAS_POP:
		// Doesn't get set because memop is not printed.
		if (ARM_get_detail(MI)->op_count == 1) {
			CS_ASSERT_RET(MI->flat_insn->usesAliasDetails && "Not valid assumption for non alias details.");
			// Only single register pop is post-indexed
			// Assumes only alias details are passed here.
			ARM_get_detail(MI)->post_index = true;
		}
		// fallthrough
	case ARM_INS_ALIAS_PUSH:
	case ARM_INS_ALIAS_VPUSH:
	case ARM_INS_ALIAS_VPOP:
		map_add_implicit_read(MI, ARM_REG_SP);
		map_add_implicit_write(MI, ARM_REG_SP);
		break;
	case ARM_INS_ALIAS_LDM: {
		bool Writeback = true;
		unsigned BaseReg = MCInst_getOpVal(MI, 0);
		for (unsigned i = 3; i < MCInst_getNumOperands(MI); ++i) {
			if (MCInst_getOpVal(MI, i) == BaseReg)
				Writeback = false;
		}
		if (Writeback && detail_is_set(MI)) {
			ARM_get_detail(MI)->operands[0].access |= CS_AC_WRITE;
			MI->flat_insn->detail->writeback = true;
		}
		break;
	}
	case ARM_INS_ALIAS_ASR:
	case ARM_INS_ALIAS_LSL:
	case ARM_INS_ALIAS_LSR:
	case ARM_INS_ALIAS_ROR: {
		unsigned shift_value = 0;
		arm_shifter shift_type = ARM_SFT_INVALID;
		switch (MCInst_getOpcode(MI)) {
		default:
			CS_ASSERT_RET(0 && "ASR, LSL, LSR, ROR alias not handled");
			return;
		case ARM_MOVsi: {
			MCOperand *MO2 = MCInst_getOperand(MI, 2);
			shift_type = (arm_shifter) ARM_AM_getSORegShOp(MCOperand_getImm(MO2));

			if (ARM_AM_getSORegShOp(MCOperand_getImm(MO2)) == ARM_AM_rrx) {
				break;
			}
			shift_value = translateShiftImm(ARM_AM_getSORegOffset(
							       MCOperand_getImm(MO2)));
			ARM_insert_detail_op_imm_at(MI, -1, shift_value, CS_AC_READ);
			break;
		}
		case ARM_MOVsr: {
			MCOperand *MO3 = MCInst_getOperand(MI, (3));
			shift_type = ARM_AM_getSORegShOp(MCOperand_getImm(MO3)) + ARM_SFT_REG;
			shift_value = MCInst_getOpVal(MI, 2);
			break;
		}
		}
		ARM_get_detail_op(MI, -2)->shift.type = shift_type;
		ARM_get_detail_op(MI, -2)->shift.value = shift_value;
		break;
	}
	}
}

/// Some instructions have their operands not defined but
/// hardcoded as string.
/// Here we add those oprands to detail.
static void ARM_add_not_defined_ops(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;

	if (MI->flat_insn->is_alias && MI->flat_insn->usesAliasDetails) {
		add_alias_details(MI);
		return;
	}

	unsigned Opcode = MCInst_getOpcode(MI);
	switch (Opcode) {
	default:
		return;
	case ARM_t2MOVsra_glue:
	case ARM_t2MOVsrl_glue:
		ARM_insert_detail_op_imm_at(MI, 2, 1, CS_AC_READ);
		break;
	case ARM_VCMPEZD:
	case ARM_VCMPZD:
	case ARM_tRSB:
	case ARM_VCMPEZH:
	case ARM_VCMPEZS:
	case ARM_VCMPZH:
	case ARM_VCMPZS:
		ARM_insert_detail_op_imm_at(MI, -1, 0, CS_AC_READ);
		break;
	case ARM_MVE_VSHLL_lws16bh:
	case ARM_MVE_VSHLL_lws16th:
	case ARM_MVE_VSHLL_lwu16bh:
	case ARM_MVE_VSHLL_lwu16th:
		ARM_insert_detail_op_imm_at(MI, 2, 16, CS_AC_READ);
		break;
	case ARM_MVE_VSHLL_lws8bh:
	case ARM_MVE_VSHLL_lws8th:
	case ARM_MVE_VSHLL_lwu8bh:
	case ARM_MVE_VSHLL_lwu8th:
		ARM_insert_detail_op_imm_at(MI, 2, 8, CS_AC_READ);
		break;
	case ARM_VCEQzv16i8:
	case ARM_VCEQzv2f32:
	case ARM_VCEQzv2i32:
	case ARM_VCEQzv4f16:
	case ARM_VCEQzv4f32:
	case ARM_VCEQzv4i16:
	case ARM_VCEQzv4i32:
	case ARM_VCEQzv8f16:
	case ARM_VCEQzv8i16:
	case ARM_VCEQzv8i8:
	case ARM_VCGEzv16i8:
	case ARM_VCGEzv2f32:
	case ARM_VCGEzv2i32:
	case ARM_VCGEzv4f16:
	case ARM_VCGEzv4f32:
	case ARM_VCGEzv4i16:
	case ARM_VCGEzv4i32:
	case ARM_VCGEzv8f16:
	case ARM_VCGEzv8i16:
	case ARM_VCGEzv8i8:
	case ARM_VCLEzv16i8:
	case ARM_VCLEzv2f32:
	case ARM_VCLEzv2i32:
	case ARM_VCLEzv4f16:
	case ARM_VCLEzv4f32:
	case ARM_VCLEzv4i16:
	case ARM_VCLEzv4i32:
	case ARM_VCLEzv8f16:
	case ARM_VCLEzv8i16:
	case ARM_VCLEzv8i8:
	case ARM_VCLTzv16i8:
	case ARM_VCLTzv2f32:
	case ARM_VCLTzv2i32:
	case ARM_VCLTzv4f16:
	case ARM_VCLTzv4f32:
	case ARM_VCLTzv4i16:
	case ARM_VCLTzv4i32:
	case ARM_VCLTzv8f16:
	case ARM_VCLTzv8i16:
	case ARM_VCLTzv8i8:
	case ARM_VCGTzv16i8:
	case ARM_VCGTzv2f32:
	case ARM_VCGTzv2i32:
	case ARM_VCGTzv4f16:
	case ARM_VCGTzv4f32:
	case ARM_VCGTzv4i16:
	case ARM_VCGTzv4i32:
	case ARM_VCGTzv8f16:
	case ARM_VCGTzv8i16:
	case ARM_VCGTzv8i8:
		ARM_insert_detail_op_imm_at(MI, 2, 0, CS_AC_READ);
		break;
	case ARM_BX_RET:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_LR, CS_AC_READ);
		break;
	case ARM_MOVPCLR:
	case ARM_t2SUBS_PC_LR:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_PC, CS_AC_WRITE);
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_LR, CS_AC_READ);
		break;
	case ARM_FMSTAT:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_APSR_NZCV,
					    CS_AC_WRITE);
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPSCR, CS_AC_READ);
		break;
	case ARM_VLDR_FPCXTNS_off:
	case ARM_VLDR_FPCXTNS_post:
	case ARM_VLDR_FPCXTNS_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPCXTNS,
					    CS_AC_WRITE);
		break;
	case ARM_VSTR_FPCXTNS_off:
	case ARM_VSTR_FPCXTNS_post:
	case ARM_VSTR_FPCXTNS_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPCXTNS, CS_AC_READ);
		break;
	case ARM_VLDR_FPCXTS_off:
	case ARM_VLDR_FPCXTS_post:
	case ARM_VLDR_FPCXTS_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPCXTS, CS_AC_WRITE);
		break;
	case ARM_VSTR_FPCXTS_off:
	case ARM_VSTR_FPCXTS_post:
	case ARM_VSTR_FPCXTS_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPCXTS, CS_AC_READ);
		break;
	case ARM_VLDR_FPSCR_NZCVQC_off:
	case ARM_VLDR_FPSCR_NZCVQC_post:
	case ARM_VLDR_FPSCR_NZCVQC_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPSCR_NZCVQC,
					    CS_AC_WRITE);
		break;
	case ARM_VSTR_FPSCR_NZCVQC_off:
	case ARM_VSTR_FPSCR_NZCVQC_post:
	case ARM_VSTR_FPSCR_NZCVQC_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPSCR_NZCVQC,
					    CS_AC_READ);
		break;
	case ARM_VMSR:
	case ARM_VLDR_FPSCR_off:
	case ARM_VLDR_FPSCR_post:
	case ARM_VLDR_FPSCR_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPSCR, CS_AC_WRITE);
		break;
	case ARM_VSTR_FPSCR_off:
	case ARM_VSTR_FPSCR_post:
	case ARM_VSTR_FPSCR_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPSCR, CS_AC_READ);
		break;
	case ARM_VLDR_P0_off:
	case ARM_VLDR_P0_post:
	case ARM_VLDR_P0_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_P0, CS_AC_WRITE);
		break;
	case ARM_VSTR_P0_off:
	case ARM_VSTR_P0_post:
	case ARM_VSTR_P0_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_P0, CS_AC_READ);
		break;
	case ARM_VLDR_VPR_off:
	case ARM_VLDR_VPR_post:
	case ARM_VLDR_VPR_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_VPR, CS_AC_WRITE);
		break;
	case ARM_VSTR_VPR_off:
	case ARM_VSTR_VPR_post:
	case ARM_VSTR_VPR_pre:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_VPR, CS_AC_READ);
		break;
	case ARM_VMSR_FPEXC:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPEXC, CS_AC_WRITE);
		break;
	case ARM_VMSR_FPINST:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPINST, CS_AC_WRITE);
		break;
	case ARM_VMSR_FPINST2:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPINST2,
					    CS_AC_WRITE);
		break;
	case ARM_VMSR_FPSID:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_FPSID, CS_AC_WRITE);
		break;
	case ARM_t2SRSDB:
	case ARM_t2SRSIA:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_SP, CS_AC_WRITE);
		break;
	case ARM_t2SRSDB_UPD:
	case ARM_t2SRSIA_UPD:
		ARM_insert_detail_op_reg_at(MI, 0, ARM_REG_SP,
					    CS_AC_READ | CS_AC_WRITE);
		break;
	case ARM_MRSsys:
	case ARM_t2MRSsys_AR:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_SPSR, CS_AC_READ);
		break;
	case ARM_MRS:
	case ARM_t2MRS_AR:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_APSR, CS_AC_READ);
		break;
	case ARM_VMRS:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPSCR, CS_AC_READ);
		break;
	case ARM_VMRS_FPCXTNS:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPCXTNS, CS_AC_READ);
		break;
	case ARM_VMRS_FPCXTS:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPCXTS, CS_AC_READ);
		break;
	case ARM_VMRS_FPEXC:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPEXC, CS_AC_READ);
		break;
	case ARM_VMRS_FPINST:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPINST, CS_AC_READ);
		break;
	case ARM_VMRS_FPINST2:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPINST2, CS_AC_READ);
		break;
	case ARM_VMRS_FPSCR_NZCVQC:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPSCR_NZCVQC,
					    CS_AC_READ);
		break;
	case ARM_VMRS_FPSID:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_FPSID, CS_AC_READ);
		break;
	case ARM_VMRS_MVFR0:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_MVFR0, CS_AC_READ);
		break;
	case ARM_VMRS_MVFR1:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_MVFR1, CS_AC_READ);
		break;
	case ARM_VMRS_MVFR2:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_MVFR2, CS_AC_READ);
		break;
	case ARM_VMRS_P0:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_P0, CS_AC_READ);
		break;
	case ARM_VMRS_VPR:
		ARM_insert_detail_op_reg_at(MI, 1, ARM_REG_VPR, CS_AC_READ);
		break;
	case ARM_MOVsr:
		// Add shift information
		ARM_get_detail(MI)->operands[1].shift.type =
			(arm_shifter)ARM_AM_getSORegShOp(
				MCInst_getOpVal(MI, 3)) + ARM_SFT_REG;
		ARM_get_detail(MI)->operands[1].shift.value =
			MCInst_getOpVal(MI, 2);
		break;
	case ARM_MOVsi:
		if (ARM_AM_getSORegShOp(MCInst_getOpVal(MI, 2)) == ARM_AM_rrx) {
			ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_RRX;
			ARM_get_detail_op(MI, -1)->shift.value =
				translateShiftImm(ARM_AM_getSORegOffset(
					MCInst_getOpVal(MI, 2)));
			return;
		}

		ARM_get_detail_op(MI, -1)->shift.type =
			(arm_shifter)ARM_AM_getSORegShOp(
				MCInst_getOpVal(MI, 2));
		ARM_get_detail_op(MI, -1)->shift.value = translateShiftImm(
			ARM_AM_getSORegOffset(MCInst_getOpVal(MI, 2)));
		break;
	case ARM_tLDMIA: {
		bool Writeback = true;
		unsigned BaseReg = MCInst_getOpVal(MI, 0);
		for (unsigned i = 3; i < MCInst_getNumOperands(MI); ++i) {
			if (MCInst_getOpVal(MI, i) == BaseReg)
				Writeback = false;
		}
		if (Writeback && detail_is_set(MI)) {
			ARM_get_detail(MI)->operands[0].access |= CS_AC_WRITE;
			MI->flat_insn->detail->writeback = true;
		}
		break;
	}
	case ARM_RFEDA_UPD:
	case ARM_RFEDB_UPD:
	case ARM_RFEIA_UPD:
	case ARM_RFEIB_UPD:
		get_detail(MI)->writeback = true;
		// fallthrough
	case ARM_RFEDA:
	case ARM_RFEDB:
	case ARM_RFEIA:
	case ARM_RFEIB: {
		arm_reg base_reg = ARM_get_detail_op(MI, -1)->reg;
		ARM_get_detail_op(MI, -1)->type = ARM_OP_MEM;
		ARM_get_detail_op(MI, -1)->mem.base = base_reg;
	}
	}
}

/// Unfortunately there is currently no way to easily extract
/// information about the vector data usage (sign and width used).
/// See: https://github.com/capstone-engine/capstone/issues/2152
void ARM_add_vector_data(MCInst *MI, arm_vectordata_type data_type)
{
	if (!detail_is_set(MI))
		return;
	ARM_get_detail(MI)->vector_data = data_type;
}

/// Unfortunately there is currently no way to easily extract
/// information about the vector size.
/// See: https://github.com/capstone-engine/capstone/issues/2152
void ARM_add_vector_size(MCInst *MI, unsigned size)
{
	if (!detail_is_set(MI))
		return;
	ARM_get_detail(MI)->vector_size = size;
}

/// For ARM the attributation of post-indexed instructions is poor.
/// Disponents or index register are sometimes not defined as such.
/// Here we try to detect such cases. We check if the base register
/// is a writeback register, but no other memory operand
/// was disassembled.
/// Because there must be a second memory operand (disponent/index)
/// We assume that the following operand is actually
/// the disponent/index reg.
static void ARM_post_index_detection(MCInst *MI)
{
	if (!detail_is_set(MI) || ARM_get_detail(MI)->post_index)
		return;

	int i = 0;
	for (; i < ARM_get_detail(MI)->op_count; ++i) {
		if (ARM_get_detail(MI)->operands[i].type & ARM_OP_MEM)
			break;
	}
	if (i >= ARM_get_detail(MI)->op_count) {
		// Last operand
		return;
	}

	cs_arm_op *op = &ARM_get_detail(MI)->operands[i];
	cs_arm_op op_next = ARM_get_detail(MI)->operands[i + 1];
	if (op_next.type == ARM_OP_INVALID || op->mem.disp != 0 || op->mem.index != ARM_REG_INVALID)
		return;

	if (op_next.type & CS_OP_IMM)
		op->mem.disp = op_next.imm;
	else if (op_next.type & CS_OP_REG)
		op->mem.index = op_next.reg;

	op->subtracted = op_next.subtracted;
	ARM_get_detail(MI)->post_index = true;
	MI->flat_insn->detail->writeback = true;
	ARM_dec_op_count(MI);
}

void ARM_check_mem_access_validity(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI))
		return;
	const arm_suppl_info *suppl = map_get_suppl_info(MI, arm_insns);
	CS_ASSERT_RET(suppl);
	if (suppl->mem_acc == CS_AC_INVALID) {
		return;
	}
	cs_detail *detail = get_detail(MI);
	for (int i = 0; i < detail->arm.op_count; ++i) {
		if (detail->arm.operands[i].type == ARM_OP_MEM && detail->arm.operands[i].access != suppl->mem_acc) {
			detail->arm.operands[i].access = suppl->mem_acc;
			return;
		}
	}
#endif // CAPSTONE_DIET
}

/// Decodes the asm string for a given instruction
/// and fills the detail information about the instruction and its operands.
void ARM_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	MI->fillDetailOps = detail_is_set(MI);
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	ARM_LLVM_printInstruction(MI, O, info);
	map_set_alias_id(MI, O, insn_alias_mnem_map, ARR_SIZE(insn_alias_mnem_map) - 1);
	ARM_add_not_defined_ops(MI);
	ARM_post_index_detection(MI);
	ARM_check_mem_access_validity(MI);
	ARM_add_cs_groups(MI);
	int syntax_opt = MI->csh->syntax;
	if (syntax_opt & CS_OPT_SYNTAX_CS_REG_ALIAS)
		patch_cs_reg_alias(O->buffer);
}

#ifndef CAPSTONE_DIET
static const char *const insn_name_maps[] = {
#include "ARMGenCSMappingInsnName.inc"
	// Hard coded alias in LLVM, not defined as alias or instruction.
	// We give them a unique ID for convenience.
	"vpop",
	"vpush",
};
#endif

#ifndef CAPSTONE_DIET
static const arm_reg arm_flag_regs[] = {
	ARM_REG_APSR,	      ARM_REG_APSR_NZCV, ARM_REG_CPSR,
	ARM_REG_FPCXTNS,      ARM_REG_FPCXTS,	 ARM_REG_FPEXC,
	ARM_REG_FPINST,	      ARM_REG_FPSCR,	 ARM_REG_FPSCR_NZCV,
	ARM_REG_FPSCR_NZCVQC,
};
#endif // CAPSTONE_DIET

const char *ARM_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < ARM_INS_ALIAS_END && id > ARM_INS_ALIAS_BEGIN) {
		if (id - ARM_INS_ALIAS_BEGIN >= ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - ARM_INS_ALIAS_BEGIN - 1].name;
	}
	if (id >= ARM_INS_ENDING)
		return NULL;

	if (id < ARR_SIZE(insn_name_maps))
		return insn_name_maps[id];

	// not found
	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ ARM_GRP_INVALID, NULL },
	{ ARM_GRP_JUMP, "jump" },
	{ ARM_GRP_CALL, "call" },
	{ ARM_GRP_RET, "return" },
	{ ARM_GRP_INT, "int" },
	{ ARM_GRP_PRIVILEGE, "privilege" },
	{ ARM_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture-specific groups
#include "ARMGenCSFeatureName.inc"
};
#endif

const char *ARM_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// list all relative branch instructions
// ie: insns[i].branch && !insns[i].indirect_branch
static const unsigned int insn_rel[] = {
	ARM_BL,	  ARM_BLX_pred, ARM_Bcc,   ARM_t2B,  ARM_t2Bcc,
	ARM_tB,	  ARM_tBcc,	ARM_tCBNZ, ARM_tCBZ, ARM_BL_pred,
	ARM_BLXi, ARM_tBL,	ARM_tBLXi, 0
};

static const unsigned int insn_blx_rel_to_arm[] = { ARM_tBLXi, 0 };

// check if this insn is relative branch
bool ARM_rel_branch(cs_struct *h, unsigned int id)
{
	int i;

	for (i = 0; insn_rel[i]; i++) {
		if (id == insn_rel[i]) {
			return true;
		}
	}

	// not found
	return false;
}

bool ARM_blx_to_arm_mode(cs_struct *h, unsigned int id)
{
	int i;

	for (i = 0; insn_blx_rel_to_arm[i]; i++)
		if (id == insn_blx_rel_to_arm[i])
			return true;

	// not found
	return false;
}

void ARM_check_updates_flags(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI))
		return;
	cs_detail *detail = get_detail(MI);
	for (int i = 0; i < detail->regs_write_count; ++i) {
		if (detail->regs_write[i] == 0)
			return;
		for (int j = 0; j < ARR_SIZE(arm_flag_regs); ++j) {
			if (detail->regs_write[i] == arm_flag_regs[j]) {
				detail->arm.update_flags = true;
				return;
			}
		}
	}
#endif // CAPSTONE_DIET
}

void ARM_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, arm_insns, ARR_SIZE(arm_insns));
	map_implicit_reads(MI, arm_insns);
	map_implicit_writes(MI, arm_insns);
	ARM_check_updates_flags(MI);
	map_groups(MI, arm_insns);
}

bool ARM_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info)
{
	ARM_init_cs_detail(instr);
	bool Result = ARM_LLVM_getInstruction(handle, code, code_len, instr,
					      size, address,
					      info) != MCDisassembler_Fail;
	ARM_set_instr_map_data(instr);
	return Result;
}

#define GET_REGINFO_MC_DESC
#include "ARMGenRegisterInfo.inc"

void ARM_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, ARMRegDesc, ARM_REG_ENDING, 0, 0,
					  ARMMCRegisterClasses,
					  ARR_SIZE(ARMMCRegisterClasses), 0, 0,
					  ARMRegDiffLists, 0, ARMSubRegIdxLists,
					  ARR_SIZE(ARMSubRegIdxLists), 0);
}

#ifndef CAPSTONE_DIET
static const map_insn_ops insn_operands[] = {
#include "ARMGenCSMappingInsnOp.inc"
};

void ARM_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arm *arm = &(insn->detail->arm);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch ((int)op->type) {
		case ARM_OP_REG:
			if ((op->access & CS_AC_READ) &&
			    !arr_exist(regs_read, read_count, op->reg)) {
				regs_read[read_count] = (uint16_t)op->reg;
				read_count++;
			}
			if ((op->access & CS_AC_WRITE) &&
			    !arr_exist(regs_write, write_count, op->reg)) {
				regs_write[write_count] = (uint16_t)op->reg;
				write_count++;
			}
			break;
		case ARM_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.base != ARM_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = (uint16_t)op->mem.base;
				read_count++;
			}
			if ((op->mem.index != ARM_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.index)) {
				regs_read[read_count] = (uint16_t)op->mem.index;
				read_count++;
			}
			if ((insn->detail->writeback) &&
			    (op->mem.base != ARM_REG_INVALID) &&
			    !arr_exist(regs_write, write_count, op->mem.base)) {
				regs_write[write_count] =
					(uint16_t)op->mem.base;
				write_count++;
			}
		default:
			break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

void ARM_setup_op(cs_arm_op *op)
{
	memset(op, 0, sizeof(cs_arm_op));
	op->type = ARM_OP_INVALID;
	op->vector_index = -1;
	op->neon_lane = -1;
}

void ARM_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		unsigned int i;

		memset(get_detail(MI), 0,
		       offsetof(cs_detail, arm) + sizeof(cs_arm));

		for (i = 0; i < ARR_SIZE(ARM_get_detail(MI)->operands); i++)
			ARM_setup_op(&ARM_get_detail(MI)->operands[i]);
		ARM_get_detail(MI)->cc = ARMCC_UNDEF;
		ARM_get_detail(MI)->vcc = ARMVCC_None;
	}
}

static uint64_t t_add_pc(MCInst *MI, uint64_t v)
{
	int32_t imm = (int32_t)v;
	if (ARM_rel_branch(MI->csh, MI->Opcode)) {
		uint32_t address;

		// only do this for relative branch
		if (MI->csh->mode & CS_MODE_THUMB) {
			address = (uint32_t)MI->address + 4;
			if (ARM_blx_to_arm_mode(MI->csh, MI->Opcode)) {
				// here need to align down to the nearest 4-byte address
#define _ALIGN_DOWN(v, align_width) ((v / align_width) * align_width)
				address = _ALIGN_DOWN(address, 4);
#undef _ALIGN_DOWN
			}
		} else {
			address = (uint32_t)MI->address + 8;
		}

		imm += address;
		return imm;
	}
	return v;
}

/// Transform a Qs register to its corresponding Ds + Offset register.
static uint64_t t_qpr_to_dpr_list(MCInst *MI, unsigned OpNum, uint8_t offset)
{
	uint64_t v = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	if (v >= ARM_REG_Q0 && v <= ARM_REG_Q15)
		return ARM_REG_D0 + offset + (v - ARM_REG_Q0) * 2;
	return v + offset;
}

static uint64_t t_mod_imm_rotate(uint64_t v)
{
	unsigned Bits = v & 0xFF;
	unsigned Rot = (v & 0xF00) >> 7;
	int32_t Rotated = ARM_AM_rotr32(Bits, Rot);
	return Rotated;
}

inline static uint64_t t_mod_imm_bits(uint64_t v)
{
	unsigned Bits = v & 0xFF;
	return Bits;
}

inline static uint64_t t_mod_imm_rot(uint64_t v)
{
	unsigned Rot = (v & 0xF00) >> 7;
	return Rot;
}

static uint64_t t_vmov_mod_imm(uint64_t v)
{
	unsigned EltBits;
	uint64_t Val = ARM_AM_decodeVMOVModImm(v, &EltBits);
	return Val;
}

/// Initializes or finishes a memory operand of Capstone (depending on \p
/// status). A memory operand in Capstone can be assembled by two LLVM operands.
/// E.g. the base register and the immediate disponent.
static void ARM_set_mem_access(MCInst *MI, bool status)
{
	if (!detail_is_set(MI))
		return;
	set_doing_mem(MI, status);
	if (status) {
		ARM_get_detail_op(MI, 0)->type = ARM_OP_MEM;
		ARM_get_detail_op(MI, 0)->mem.base = ARM_REG_INVALID;
		ARM_get_detail_op(MI, 0)->mem.index = ARM_REG_INVALID;
		ARM_get_detail_op(MI, 0)->mem.scale = 1;
		ARM_get_detail_op(MI, 0)->mem.disp = 0;

#ifndef CAPSTONE_DIET
		uint8_t access =
			map_get_op_access(MI, ARM_get_detail(MI)->op_count);
		ARM_get_detail_op(MI, 0)->access = access;
#endif
	} else {
		// done, select the next operand slot
		ARM_check_safe_inc(MI);
		ARM_inc_op_count(MI);
	}
}

/// Fills cs_detail with operand shift information for the last added operand.
static void add_cs_detail_RegImmShift(MCInst *MI, ARM_AM_ShiftOpc ShOpc,
				      unsigned ShImm)
{
	if (ShOpc == ARM_AM_no_shift || (ShOpc == ARM_AM_lsl && !ShImm))
		return;

	if (!detail_is_set(MI))
		return;

	if (doing_mem(MI))
		ARM_get_detail_op(MI, 0)->shift.type = (arm_shifter)ShOpc;
	else
		ARM_get_detail_op(MI, -1)->shift.type = (arm_shifter)ShOpc;

	if (ShOpc != ARM_AM_rrx) {
		if (doing_mem(MI))
			ARM_get_detail_op(MI, 0)->shift.value =
				translateShiftImm(ShImm);
		else
			ARM_get_detail_op(MI, -1)->shift.value =
				translateShiftImm(ShImm);
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function has no
/// specialities.
static void add_cs_detail_general(MCInst *MI, arm_op_group op_group,
				  unsigned OpNum)
{
	if (!detail_is_set(MI))
		return;
	cs_op_type op_type = map_get_op_type(MI, OpNum);

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		CS_ASSERT_RET(0);
	case ARM_OP_GROUP_PredicateOperand:
	case ARM_OP_GROUP_MandatoryPredicateOperand:
	case ARM_OP_GROUP_MandatoryInvertedPredicateOperand:
	case ARM_OP_GROUP_MandatoryRestrictedPredicateOperand: {
		ARMCC_CondCodes CC = (ARMCC_CondCodes)MCOperand_getImm(
			MCInst_getOperand(MI, OpNum));
		if ((unsigned)CC == 15 &&
		    op_group == ARM_OP_GROUP_PredicateOperand) {
			ARM_get_detail(MI)->cc = ARMCC_UNDEF;
			return;
		}
		if (CC == ARMCC_HS &&
		    op_group ==
			    ARM_OP_GROUP_MandatoryRestrictedPredicateOperand) {
			ARM_get_detail(MI)->cc = ARMCC_HS;
			return;
		}
		ARM_get_detail(MI)->cc = CC;
		if (CC != ARMCC_AL)
			map_add_implicit_read(MI, ARM_REG_CPSR);
		break;
	}
	case ARM_OP_GROUP_VPTPredicateOperand: {
		ARMVCC_VPTCodes VCC = (ARMVCC_VPTCodes)MCOperand_getImm(
			MCInst_getOperand(MI, OpNum));
		CS_ASSERT_RET(VCC <= ARMVCC_Else);
		if (VCC != ARMVCC_None)
			ARM_get_detail(MI)->vcc = VCC;
		break;
	}
	case ARM_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			if (doing_mem(MI)) {
				ARM_set_detail_op_mem(MI, OpNum, false, 0,
						      MCInst_getOpVal(MI,
								      OpNum));
			} else {
				ARM_set_detail_op_imm(
					MI, OpNum, ARM_OP_IMM,
					t_add_pc(MI,
						 MCInst_getOpVal(MI, OpNum)));
			}
		} else if (op_type == CS_OP_REG)
			if (doing_mem(MI)) {
				bool is_index_reg = map_get_op_type(MI, OpNum) &
						    CS_OP_MEM;
				ARM_set_detail_op_mem(
					MI, OpNum, is_index_reg, is_index_reg ? 1 : 0,
					MCInst_getOpVal(MI, OpNum));
			} else {
				ARM_set_detail_op_reg(
					MI, OpNum, MCInst_getOpVal(MI, OpNum));
			}
		else
			CS_ASSERT_RET(0 && "Op type not handled.");
		break;
	case ARM_OP_GROUP_PImmediate:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_PIMM,
				      MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_CImmediate:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_CIMM,
				      MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_AddrMode6Operand:
		if (!doing_mem(MI))
			ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		ARM_get_detail_op(MI, 0)->mem.align =
			MCInst_getOpVal(MI, OpNum + 1) << 3;
		ARM_set_mem_access(MI, false);
		break;
	case ARM_OP_GROUP_AddrMode6OffsetOperand: {
		arm_reg reg = MCInst_getOpVal(MI, OpNum);
		if (reg != 0) {
			ARM_set_detail_op_mem_offset(MI, OpNum, reg, false);
		}
		break;
	}
	case ARM_OP_GROUP_AddrMode7Operand:
		if (!doing_mem(MI))
			ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		ARM_set_mem_access(MI, false);
		break;
	case ARM_OP_GROUP_SBitModifierOperand: {
		unsigned SBit = MCInst_getOpVal(MI, OpNum);

		if (SBit == 0) {
			// Does not edit set flags.
			map_remove_implicit_write(MI, ARM_CPSR);
			ARM_get_detail(MI)->update_flags = false;
			break;
		}
		// Add the implicit write again. Some instruction miss it.
		map_add_implicit_write(MI, ARM_CPSR);
		ARM_get_detail(MI)->update_flags = true;
		break;
	}
	case ARM_OP_GROUP_VectorListOne:
	case ARM_OP_GROUP_VectorListOneAllLanes:
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 0));
		break;
	case ARM_OP_GROUP_VectorListTwo:
	case ARM_OP_GROUP_VectorListTwoAllLanes: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_dsub_0));
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_dsub_1));
		break;
	}
	case ARM_OP_GROUP_VectorListTwoSpacedAllLanes:
	case ARM_OP_GROUP_VectorListTwoSpaced: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_dsub_0));
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_dsub_2));
		break;
	}
	case ARM_OP_GROUP_VectorListThree:
	case ARM_OP_GROUP_VectorListThreeAllLanes:
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 0));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 1));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 2));
		break;
	case ARM_OP_GROUP_VectorListThreeSpacedAllLanes:
	case ARM_OP_GROUP_VectorListThreeSpaced:
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 0));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 2));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 4));
		break;
	case ARM_OP_GROUP_VectorListFour:
	case ARM_OP_GROUP_VectorListFourAllLanes:
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 0));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 1));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 2));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 3));
		break;
	case ARM_OP_GROUP_VectorListFourSpacedAllLanes:
	case ARM_OP_GROUP_VectorListFourSpaced:
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 0));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 2));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 4));
		ARM_set_detail_op_reg(MI, OpNum,
				      t_qpr_to_dpr_list(MI, OpNum, 6));
		break;
	case ARM_OP_GROUP_NoHashImmediate:
		ARM_set_detail_op_neon_lane(MI, OpNum);
		break;
	case ARM_OP_GROUP_RegisterList: {
		// All operands n MI from OpNum on are registers.
		// But the MappingInsnOps.inc has only a single entry for the whole
		// list. So all registers in the list share those attributes.
		unsigned access = map_get_op_access(MI, OpNum);
		for (unsigned i = OpNum, e = MCInst_getNumOperands(MI); i != e;
		     ++i) {
			unsigned Reg =
				MCOperand_getReg(MCInst_getOperand(MI, i));

			ARM_check_safe_inc(MI);
			ARM_get_detail_op(MI, 0)->type = ARM_OP_REG;
			ARM_get_detail_op(MI, 0)->reg = Reg;
			ARM_get_detail_op(MI, 0)->access = access;
			ARM_inc_op_count(MI);
		}
		break;
	}
	case ARM_OP_GROUP_ThumbITMask: {
		unsigned Mask = MCInst_getOpVal(MI, OpNum);
		unsigned Firstcond = MCInst_getOpVal(MI, OpNum - 1);
		unsigned CondBit0 = Firstcond & 1;
		unsigned NumTZ = CountTrailingZeros_32(Mask);
		unsigned Pos, e;
		ARM_PredBlockMask PredMask = ARM_PredBlockMaskInvalid;

		// Check the documentation of ARM_PredBlockMask how the bits are set.
		for (Pos = 3, e = NumTZ; Pos > e; --Pos) {
			bool Then = ((Mask >> Pos) & 1) == CondBit0;
			if (Then)
				PredMask <<= 1;
			else {
				PredMask |= 1;
				PredMask <<= 1;
			}
		}
		PredMask |= 1;
		ARM_get_detail(MI)->pred_mask = PredMask;
		break;
	}
	case ARM_OP_GROUP_VPTMask: {
		unsigned Mask = MCInst_getOpVal(MI, OpNum);
		unsigned NumTZ = CountTrailingZeros_32(Mask);
		ARM_PredBlockMask PredMask = ARM_PredBlockMaskInvalid;

		// Check the documentation of ARM_PredBlockMask how the bits are set.
		for (unsigned Pos = 3, e = NumTZ; Pos > e; --Pos) {
			bool T = ((Mask >> Pos) & 1) == 0;
			if (T)
				PredMask <<= 1;
			else {
				PredMask |= 1;
				PredMask <<= 1;
			}
		}
		PredMask |= 1;
		ARM_get_detail(MI)->pred_mask = PredMask;
		break;
	}
	case ARM_OP_GROUP_MSRMaskOperand: {
		MCOperand *Op = MCInst_getOperand(MI, OpNum);
		unsigned SpecRegRBit = (unsigned)MCOperand_getImm(Op) >> 4;
		unsigned Mask = (unsigned)MCOperand_getImm(Op) & 0xf;
		bool IsOutReg = OpNum == 0;

		if (ARM_getFeatureBits(MI->csh->mode, ARM_FeatureMClass)) {
			const ARMSysReg_MClassSysReg *TheReg;
			unsigned SYSm = (unsigned)MCOperand_getImm(Op) &
					0xFFF; // 12-bit SYMm
			unsigned Opcode = MCInst_getOpcode(MI);

			if (Opcode == ARM_t2MSR_M &&
			    ARM_getFeatureBits(MI->csh->mode, ARM_FeatureDSP)) {
				TheReg =
					ARMSysReg_lookupMClassSysRegBy12bitSYSmValue(
						SYSm);
				if (TheReg && MClassSysReg_isInRequiredFeatures(
						      TheReg, ARM_FeatureDSP)) {
					ARM_set_detail_op_sysop(
						MI, TheReg->sysreg.mclasssysreg,
						ARM_OP_SYSREG, IsOutReg, Mask,
						SYSm);
					return;
				}
			}

			SYSm &= 0xff;
			if (Opcode == ARM_t2MSR_M &&
			    ARM_getFeatureBits(MI->csh->mode, ARM_HasV7Ops)) {
				TheReg =
					ARMSysReg_lookupMClassSysRegAPSRNonDeprecated(
						SYSm);
				if (TheReg) {
					ARM_set_detail_op_sysop(
						MI, TheReg->sysreg.mclasssysreg,
						ARM_OP_SYSREG, IsOutReg, Mask,
						SYSm);
					return;
				}
			}

			TheReg = ARMSysReg_lookupMClassSysRegBy8bitSYSmValue(
				SYSm);
			if (TheReg) {
				ARM_set_detail_op_sysop(
					MI, TheReg->sysreg.mclasssysreg,
					ARM_OP_SYSREG, IsOutReg, Mask, SYSm);
				return;
			}

			if (detail_is_set(MI))
				MCOperand_CreateImm0(MI, SYSm);

			ARM_set_detail_op_sysop(MI, SYSm, ARM_OP_SYSREG,
						IsOutReg, Mask, SYSm);

			return;
		}

		if (!SpecRegRBit && (Mask == 8 || Mask == 4 || Mask == 12)) {
			switch (Mask) {
			default:
				CS_ASSERT_RET(0 && "Unexpected mask value!");
			case 4:
				ARM_set_detail_op_sysop(MI,
							ARM_MCLASSSYSREG_APSR_G,
							ARM_OP_SYSREG, IsOutReg,
							Mask, UINT16_MAX);
				return;
			case 8:
				ARM_set_detail_op_sysop(
					MI, ARM_MCLASSSYSREG_APSR_NZCVQ,
					ARM_OP_SYSREG, IsOutReg, Mask,
					UINT16_MAX);
				return;
			case 12:
				ARM_set_detail_op_sysop(
					MI, ARM_MCLASSSYSREG_APSR_NZCVQG,
					ARM_OP_SYSREG, IsOutReg, Mask,
					UINT16_MAX);
				return;
			}
		}

		unsigned field = 0;
		if (Mask) {
			if (Mask & 8)
				field += SpecRegRBit ? ARM_FIELD_SPSR_F :
						       ARM_FIELD_CPSR_F;
			if (Mask & 4)
				field += SpecRegRBit ? ARM_FIELD_SPSR_S :
						       ARM_FIELD_CPSR_S;
			if (Mask & 2)
				field += SpecRegRBit ? ARM_FIELD_SPSR_X :
						       ARM_FIELD_CPSR_X;
			if (Mask & 1)
				field += SpecRegRBit ? ARM_FIELD_SPSR_C :
						       ARM_FIELD_CPSR_C;

			ARM_set_detail_op_sysop(MI, field,
						SpecRegRBit ? ARM_OP_SPSR :
							      ARM_OP_CPSR,
						IsOutReg, Mask, UINT16_MAX);
		}
		break;
	}
	case ARM_OP_GROUP_SORegRegOperand: {
		int64_t imm =
			MCOperand_getImm(MCInst_getOperand(MI, OpNum + 2));
		ARM_get_detail_op(MI, 0)->shift.type =
			ARM_AM_getSORegShOp(imm) + ARM_SFT_REG;
		if (ARM_AM_getSORegShOp(imm) != ARM_AM_rrx)
			ARM_get_detail_op(MI, 0)->shift.value =
				MCInst_getOpVal(MI, OpNum + 1);

		ARM_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		break;
	}
	case ARM_OP_GROUP_ModImmOperand: {
		int64_t imm = MCInst_getOpVal(MI, OpNum);
		int32_t Rotated = t_mod_imm_rotate(imm);
		if (ARM_AM_getSOImmVal(Rotated) == imm) {
			ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
					      t_mod_imm_rotate(imm));
			return;
		}
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      t_mod_imm_bits(imm));
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      t_mod_imm_rot(imm));
		break;
	}
	case ARM_OP_GROUP_VMOVModImmOperand:
		ARM_set_detail_op_imm(
			MI, OpNum, ARM_OP_IMM,
			t_vmov_mod_imm(MCInst_getOpVal(MI, OpNum)));
		break;
	case ARM_OP_GROUP_FPImmOperand:
		ARM_set_detail_op_float(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_ImmPlusOneOperand:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      MCInst_getOpVal(MI, OpNum) + 1);
		break;
	case ARM_OP_GROUP_RotImmOperand: {
		unsigned RotImm = MCInst_getOpVal(MI, OpNum);
		if (RotImm == 0)
			return;
		ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_ROR;
		ARM_get_detail_op(MI, -1)->shift.value = RotImm * 8;
		break;
	}
	case ARM_OP_GROUP_FBits16:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      16 - MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_FBits32:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      32 - MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_T2SOOperand:
	case ARM_OP_GROUP_SORegImmOperand:
		ARM_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		uint64_t imm = MCInst_getOpVal(MI, OpNum + 1);
		ARM_AM_ShiftOpc ShOpc = ARM_AM_getSORegShOp(imm);
		unsigned ShImm = ARM_AM_getSORegOffset(imm);
		if (op_group == ARM_OP_GROUP_SORegImmOperand) {
			if (ShOpc == ARM_AM_no_shift ||
			    (ShOpc == ARM_AM_lsl && !ShImm))
				return;
		}
		add_cs_detail_RegImmShift(MI, ShOpc, ShImm);
		break;
	case ARM_OP_GROUP_PostIdxRegOperand: {
		bool sub = MCInst_getOpVal(MI, OpNum + 1) ? false : true;
		ARM_set_detail_op_mem_offset(MI, OpNum,
					     MCInst_getOpVal(MI, OpNum), sub);
		ARM_get_detail(MI)->post_index = true;
		break;
	}
	case ARM_OP_GROUP_PostIdxImm8Operand: {
		unsigned Imm8 = MCInst_getOpVal(MI, OpNum);
		bool sub = !(Imm8 & 256);
		ARM_set_detail_op_mem_offset(MI, OpNum, (Imm8 & 0xff), sub);
		ARM_get_detail(MI)->post_index = true;
		break;
	}
	case ARM_OP_GROUP_PostIdxImm8s4Operand: {
		unsigned Imm8s = MCInst_getOpVal(MI, OpNum);
		bool sub = !(Imm8s & 256);
		ARM_set_detail_op_mem_offset(MI, OpNum, (Imm8s & 0xff) << 2, sub);
		ARM_get_detail(MI)->post_index = true;
		break;
	}
	case ARM_OP_GROUP_AddrModeTBB:
	case ARM_OP_GROUP_AddrModeTBH:
		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		ARM_set_detail_op_mem(MI, OpNum + 1, true, 1,
				      MCInst_getOpVal(MI, OpNum + 1));
		if (op_group == ARM_OP_GROUP_AddrModeTBH) {
			ARM_get_detail_op(MI, 0)->shift.type = ARM_SFT_LSL;
			ARM_get_detail_op(MI, 0)->shift.value = 1;
		}
		ARM_set_mem_access(MI, false);
		break;
	case ARM_OP_GROUP_AddrMode2Operand: {
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		if (!MCOperand_isReg(MO1))
			// Handled in printOperand
			break;

		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		unsigned int imm3 = MCInst_getOpVal(MI, OpNum + 2);
		unsigned ShOff = ARM_AM_getAM2Offset(imm3);
		ARM_AM_AddrOpc subtracted = ARM_AM_getAM2Op(imm3);
		if (!MCOperand_getReg(MCInst_getOperand(MI, OpNum + 1)) &&
		    ShOff) {
			ARM_get_detail_op(MI, 0)->shift.value = ShOff;
			ARM_get_detail_op(MI, 0)->subtracted = subtracted ==
							       ARM_AM_sub;
			ARM_set_mem_access(MI, false);
			break;
		}
		ARM_set_detail_op_mem(MI, OpNum + 1, true, subtracted == ARM_AM_sub ? -1 : 1,
				      MCInst_getOpVal(MI, OpNum + 1));
		add_cs_detail_RegImmShift(MI, ARM_AM_getAM2ShiftOpc(imm3),
					  ARM_AM_getAM2Offset(imm3));
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_AddrMode2OffsetOperand: {
		uint64_t imm2 = MCInst_getOpVal(MI, OpNum + 1);
		ARM_AM_AddrOpc subtracted = ARM_AM_getAM2Op(imm2);
		if (!MCInst_getOpVal(MI, OpNum)) {
			ARM_set_detail_op_mem_offset(MI, OpNum + 1,
						     ARM_AM_getAM2Offset(imm2),
						     subtracted == ARM_AM_sub);
			ARM_get_detail(MI)->post_index = true;
			return;
		}
		ARM_set_detail_op_mem_offset(MI, OpNum,
					     MCInst_getOpVal(MI, OpNum),
					     subtracted == ARM_AM_sub);
		ARM_get_detail(MI)->post_index = true;
		add_cs_detail_RegImmShift(MI, ARM_AM_getAM2ShiftOpc(imm2),
					  ARM_AM_getAM2Offset(imm2));
		break;
	}
	case ARM_OP_GROUP_AddrMode3OffsetOperand: {
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		MCOperand *MO2 = MCInst_getOperand(MI, OpNum + 1);
		ARM_AM_AddrOpc subtracted =
			ARM_AM_getAM3Op(MCOperand_getImm(MO2));
		if (MCOperand_getReg(MO1)) {
			ARM_set_detail_op_mem_offset(MI, OpNum,
						     MCInst_getOpVal(MI, OpNum),
						     subtracted == ARM_AM_sub);
			ARM_get_detail(MI)->post_index = true;
			return;
		}
		ARM_set_detail_op_mem_offset(
			MI, OpNum + 1,
			ARM_AM_getAM3Offset(MCInst_getOpVal(MI, OpNum + 1)),
			subtracted == ARM_AM_sub);
		ARM_get_detail(MI)->post_index = true;
		break;
	}
	case ARM_OP_GROUP_ThumbAddrModeSPOperand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S1Operand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S2Operand:
	case ARM_OP_GROUP_ThumbAddrModeImm5S4Operand: {
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		if (!MCOperand_isReg(MO1))
			// Handled in printOperand
			break;

		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		unsigned ImmOffs = MCInst_getOpVal(MI, OpNum + 1);
		if (ImmOffs) {
			unsigned Scale = 0;
			switch (op_group) {
			default:
				CS_ASSERT_RET(0 &&
				       "Cannot determine scale. Operand group not handled.");
			case ARM_OP_GROUP_ThumbAddrModeImm5S1Operand:
				Scale = 1;
				break;
			case ARM_OP_GROUP_ThumbAddrModeImm5S2Operand:
				Scale = 2;
				break;
			case ARM_OP_GROUP_ThumbAddrModeImm5S4Operand:
			case ARM_OP_GROUP_ThumbAddrModeSPOperand:
				Scale = 4;
				break;
			}
			ARM_set_detail_op_mem(MI, OpNum + 1, false, 0,
					      ImmOffs * Scale);
		}
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_ThumbAddrModeRROperand: {
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		if (!MCOperand_isReg(MO1))
			// Handled in printOperand
			break;

		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		arm_reg RegNum = MCInst_getOpVal(MI, OpNum + 1);
		if (RegNum)
			ARM_set_detail_op_mem(MI, OpNum + 1, true, 1,
					      RegNum);
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_T2AddrModeImm8OffsetOperand:
	case ARM_OP_GROUP_T2AddrModeImm8s4OffsetOperand: {
		int32_t OffImm = MCInst_getOpVal(MI, OpNum);
		if (OffImm == INT32_MIN)
			ARM_set_detail_op_mem_offset(MI, OpNum, 0, false);
		else {
			bool sub = OffImm < 0;
			OffImm = OffImm < 0 ? OffImm * -1 : OffImm;
			ARM_set_detail_op_mem_offset(MI, OpNum, OffImm, sub);
		}
		ARM_get_detail(MI)->post_index = true;
		break;
	}
	case ARM_OP_GROUP_T2AddrModeSoRegOperand: {
		if (!doing_mem(MI))
			ARM_set_mem_access(MI, true);

		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		ARM_set_detail_op_mem(MI, OpNum + 1, true, 1,
				      MCInst_getOpVal(MI, OpNum + 1));
		unsigned ShAmt = MCInst_getOpVal(MI, OpNum + 2);
		if (ShAmt) {
			ARM_get_detail_op(MI, 0)->shift.type = ARM_SFT_LSL;
			ARM_get_detail_op(MI, 0)->shift.value = ShAmt;
		}
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_T2AddrModeImm0_1020s4Operand:
		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		int64_t Imm0_1024s4 = MCInst_getOpVal(MI, OpNum + 1);
		if (Imm0_1024s4)
			ARM_set_detail_op_mem(MI, OpNum + 1, false, 0,
					      Imm0_1024s4 * 4);
		ARM_set_mem_access(MI, false);
		break;
	case ARM_OP_GROUP_PKHLSLShiftImm: {
		unsigned ShiftImm = MCInst_getOpVal(MI, OpNum);
		if (ShiftImm == 0)
			return;
		ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_LSL;
		ARM_get_detail_op(MI, -1)->shift.value = ShiftImm;
		break;
	}
	case ARM_OP_GROUP_PKHASRShiftImm: {
		unsigned RShiftImm = MCInst_getOpVal(MI, OpNum);
		if (RShiftImm == 0)
			RShiftImm = 32;
		ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_ASR;
		ARM_get_detail_op(MI, -1)->shift.value = RShiftImm;
		break;
	}
	case ARM_OP_GROUP_ThumbS4ImmOperand:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      MCInst_getOpVal(MI, OpNum) * 4);
		break;
	case ARM_OP_GROUP_ThumbSRImm: {
		unsigned SRImm = MCInst_getOpVal(MI, OpNum);
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      SRImm == 0 ? 32 : SRImm);
		break;
	}
	case ARM_OP_GROUP_BitfieldInvMaskImmOperand: {
		uint32_t v = ~MCInst_getOpVal(MI, OpNum);
		int32_t lsb = CountTrailingZeros_32(v);
		int32_t width = (32 - countLeadingZeros(v)) - lsb;
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, lsb);
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, width);
		break;
	}
	case ARM_OP_GROUP_CPSIMod: {
		unsigned Mode = MCInst_getOpVal(MI, OpNum);
		ARM_get_detail(MI)->cps_mode = Mode;
		break;
	}
	case ARM_OP_GROUP_CPSIFlag: {
		unsigned IFlags = MCInst_getOpVal(MI, OpNum);
		ARM_get_detail(MI)->cps_flag = IFlags == 0 ? ARM_CPSFLAG_NONE :
							     IFlags;
		break;
	}
	case ARM_OP_GROUP_GPRPairOperand: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_gsub_0));
		ARM_set_detail_op_reg(MI, OpNum,
				      MCRegisterInfo_getSubReg(MI->MRI, Reg,
							       ARM_gsub_1));
		break;
	}
	case ARM_OP_GROUP_MemBOption:
	case ARM_OP_GROUP_InstSyncBOption:
	case ARM_OP_GROUP_TraceSyncBOption:
		ARM_get_detail(MI)->mem_barrier = MCInst_getOpVal(MI, OpNum);
		break;
	case ARM_OP_GROUP_ShiftImmOperand: {
		unsigned ShiftOp = MCInst_getOpVal(MI, OpNum);
		bool isASR = (ShiftOp & (1 << 5)) != 0;
		unsigned Amt = ShiftOp & 0x1f;
		if (isASR) {
			unsigned tmp = Amt == 0 ? 32 : Amt;
			ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_ASR;
			ARM_get_detail_op(MI, -1)->shift.value = tmp;
		} else if (Amt) {
			ARM_get_detail_op(MI, -1)->shift.type = ARM_SFT_LSL;
			ARM_get_detail_op(MI, -1)->shift.value = Amt;
		}
		break;
	}
	case ARM_OP_GROUP_VectorIndex:
		ARM_get_detail_op(MI, -1)->vector_index =
			MCInst_getOpVal(MI, OpNum);
		break;
	case ARM_OP_GROUP_CoprocOptionImm:
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM,
				      MCInst_getOpVal(MI, OpNum));
		break;
	case ARM_OP_GROUP_ThumbLdrLabelOperand: {
		int32_t OffImm = MCInst_getOpVal(MI, OpNum);
		if (OffImm == INT32_MIN)
			OffImm = 0;
		ARM_check_safe_inc(MI);
		ARM_get_detail_op(MI, 0)->type = ARM_OP_MEM;
		ARM_get_detail_op(MI, 0)->mem.base = ARM_REG_PC;
		ARM_get_detail_op(MI, 0)->mem.index = ARM_REG_INVALID;
		ARM_get_detail_op(MI, 0)->mem.scale = 1;
		ARM_get_detail_op(MI, 0)->mem.disp = OffImm;
		ARM_get_detail_op(MI, 0)->access = CS_AC_READ;
		ARM_inc_op_count(MI);
		break;
	}
	case ARM_OP_GROUP_BankedRegOperand: {
		uint32_t Banked = MCInst_getOpVal(MI, OpNum);
		const ARMBankedReg_BankedReg *TheReg =
			ARMBankedReg_lookupBankedRegByEncoding(Banked);
		bool IsOutReg = OpNum == 0;
		ARM_set_detail_op_sysop(MI, TheReg->sysreg.bankedreg,
					ARM_OP_BANKEDREG, IsOutReg, UINT8_MAX,
					TheReg->Encoding &
						0xf); // Bit[4:0] are SYSm
		break;
	}
	case ARM_OP_GROUP_SetendOperand: {
		bool be = MCInst_getOpVal(MI, OpNum) != 0;
		ARM_check_safe_inc(MI);
		if (be) {
			ARM_get_detail_op(MI, 0)->type = ARM_OP_SETEND;
			ARM_get_detail_op(MI, 0)->setend = ARM_SETEND_BE;
		} else {
			ARM_get_detail_op(MI, 0)->type = ARM_OP_SETEND;
			ARM_get_detail_op(MI, 0)->setend = ARM_SETEND_LE;
		}
		ARM_inc_op_count(MI);
		break;
	}
	case ARM_OP_GROUP_MveSaturateOp: {
		uint32_t Val = MCInst_getOpVal(MI, OpNum);
		Val = Val == 1 ? 48 : 64;
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, Val);
		break;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which original printer function is a template
/// with one argument.
static void add_cs_detail_template_1(MCInst *MI, arm_op_group op_group,
				     unsigned OpNum, uint64_t temp_arg_0)
{
	if (!detail_is_set(MI))
		return;
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		CS_ASSERT_RET(0);
	case ARM_OP_GROUP_AddrModeImm12Operand_0:
	case ARM_OP_GROUP_AddrModeImm12Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_1: {
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		if (!MCOperand_isReg(MO1))
			// Handled in printOperand
			return;
	}
	// fallthrough
	case ARM_OP_GROUP_T2AddrModeImm8Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_1: {
		bool AlwaysPrintImm0 = temp_arg_0;
		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		int32_t Imm8 = MCInst_getOpVal(MI, OpNum + 1);
		if (Imm8 == INT32_MIN)
			Imm8 = 0;
		ARM_set_detail_op_mem(MI, OpNum + 1, false, 0, Imm8);
		if (AlwaysPrintImm0)
			map_add_implicit_write(MI, MCInst_getOpVal(MI, OpNum));

		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_AdrLabelOperand_0:
	case ARM_OP_GROUP_AdrLabelOperand_2: {
		unsigned Scale = temp_arg_0;
		int32_t OffImm = MCInst_getOpVal(MI, OpNum) << Scale;
		if (OffImm == INT32_MIN)
			OffImm = 0;
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, OffImm);
		break;
	}
	case ARM_OP_GROUP_AddrMode3Operand_0:
	case ARM_OP_GROUP_AddrMode3Operand_1: {
		bool AlwaysPrintImm0 = temp_arg_0;
		MCOperand *MO1 = MCInst_getOperand(MI, OpNum);
		if (!MCOperand_isReg(MO1))
			// Handled in printOperand
			break;

		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));

		MCOperand *MO2 = MCInst_getOperand(MI, OpNum + 1);
		ARM_AM_AddrOpc Sign =
			ARM_AM_getAM3Op(MCInst_getOpVal(MI, OpNum + 2));

		if (MCOperand_getReg(MO2)) {
			ARM_set_detail_op_mem(MI, OpNum + 1, true, Sign == ARM_AM_sub ? -1 : 1,
					      MCInst_getOpVal(MI, OpNum + 1));
			ARM_get_detail_op(MI, 0)->subtracted = Sign ==
							       ARM_AM_sub;
			ARM_set_mem_access(MI, false);
			break;
		}
		unsigned ImmOffs =
			ARM_AM_getAM3Offset(MCInst_getOpVal(MI, OpNum + 2));

		if (AlwaysPrintImm0 || ImmOffs || Sign == ARM_AM_sub) {
			ARM_set_detail_op_mem(MI, OpNum + 2, false, 0,
					      ImmOffs);
			ARM_get_detail_op(MI, 0)->subtracted = Sign ==
							       ARM_AM_sub;
		}
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_AddrMode5Operand_0:
	case ARM_OP_GROUP_AddrMode5Operand_1:
	case ARM_OP_GROUP_AddrMode5FP16Operand_0: {
		bool AlwaysPrintImm0 = temp_arg_0;

		if (AlwaysPrintImm0) {
			get_detail(MI)->writeback = true;
			map_add_implicit_write(MI, MCInst_getOpVal(MI, OpNum));
		}

		ARM_check_safe_inc(MI);
		cs_arm_op *Op = ARM_get_detail_op(MI, 0);
		Op->type = ARM_OP_MEM;
		Op->mem.base = MCInst_getOpVal(MI, OpNum);
		Op->mem.index = ARM_REG_INVALID;
		Op->mem.scale = 1;
		Op->mem.disp = 0;
		Op->access = CS_AC_READ;

		ARM_AM_AddrOpc SubFlag =
			ARM_AM_getAM5Op(MCInst_getOpVal(MI, OpNum + 1));
		unsigned ImmOffs =
			ARM_AM_getAM5Offset(MCInst_getOpVal(MI, OpNum + 1));

		if (AlwaysPrintImm0 || ImmOffs || SubFlag == ARM_AM_sub) {
			if (op_group == ARM_OP_GROUP_AddrMode5FP16Operand_0) {
				Op->mem.disp = ImmOffs * 2;
			} else {
				Op->mem.disp = ImmOffs * 4;
			}
			Op->subtracted = SubFlag == ARM_AM_sub;
		}
		ARM_inc_op_count(MI);
		break;
	}
	case ARM_OP_GROUP_MveAddrModeRQOperand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_1:
	case ARM_OP_GROUP_MveAddrModeRQOperand_2:
	case ARM_OP_GROUP_MveAddrModeRQOperand_3: {
		unsigned Shift = temp_arg_0;
		ARM_set_mem_access(MI, true);
		ARM_set_detail_op_mem(MI, OpNum, false, 0,
				      MCInst_getOpVal(MI, OpNum));
		ARM_set_detail_op_mem(MI, OpNum + 1, true, 1,
				      MCInst_getOpVal(MI, OpNum + 1));
		if (Shift > 0) {
			add_cs_detail_RegImmShift(MI, ARM_AM_uxtw, Shift);
		}
		ARM_set_mem_access(MI, false);
		break;
	}
	case ARM_OP_GROUP_MVEVectorList_2:
	case ARM_OP_GROUP_MVEVectorList_4: {
		unsigned NumRegs = temp_arg_0;
		arm_reg Reg = MCInst_getOpVal(MI, OpNum);
		for (unsigned i = 0; i < NumRegs; ++i) {
			arm_reg SubReg = MCRegisterInfo_getSubReg(
				MI->MRI, Reg, ARM_qsub_0 + i);
			ARM_set_detail_op_reg(MI, OpNum, SubReg);
		}
		break;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function is a
/// template with two arguments.
static void add_cs_detail_template_2(MCInst *MI, arm_op_group op_group,
				     unsigned OpNum, uint64_t temp_arg_0,
				     uint64_t temp_arg_1)
{
	if (!detail_is_set(MI))
		return;
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		CS_ASSERT_RET(0);
	case ARM_OP_GROUP_ComplexRotationOp_90_0:
	case ARM_OP_GROUP_ComplexRotationOp_180_90: {
		unsigned Angle = temp_arg_0;
		unsigned Remainder = temp_arg_1;
		unsigned Rotation = (MCInst_getOpVal(MI, OpNum) * Angle) + Remainder;
		ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, Rotation);
		break;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// Calls to this function are should not be added by hand! Please checkout the
/// patch `AddCSDetail` of the CppTranslator.
void ARM_add_cs_detail(MCInst *MI, int /* arm_op_group */ op_group,
		       va_list args)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;
	switch (op_group) {
	case ARM_OP_GROUP_RegImmShift: {
		ARM_AM_ShiftOpc shift_opc = va_arg(args, ARM_AM_ShiftOpc);
		unsigned shift_imm = va_arg(args, unsigned);
		add_cs_detail_RegImmShift(MI, shift_opc, shift_imm);
		return;
	}
	case ARM_OP_GROUP_AdrLabelOperand_0:
	case ARM_OP_GROUP_AdrLabelOperand_2:
	case ARM_OP_GROUP_AddrMode3Operand_0:
	case ARM_OP_GROUP_AddrMode3Operand_1:
	case ARM_OP_GROUP_AddrMode5Operand_0:
	case ARM_OP_GROUP_AddrMode5Operand_1:
	case ARM_OP_GROUP_AddrModeImm12Operand_0:
	case ARM_OP_GROUP_AddrModeImm12Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8Operand_1:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_0:
	case ARM_OP_GROUP_T2AddrModeImm8s4Operand_1:
	case ARM_OP_GROUP_MVEVectorList_2:
	case ARM_OP_GROUP_MVEVectorList_4:
	case ARM_OP_GROUP_AddrMode5FP16Operand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_0:
	case ARM_OP_GROUP_MveAddrModeRQOperand_3:
	case ARM_OP_GROUP_MveAddrModeRQOperand_1:
	case ARM_OP_GROUP_MveAddrModeRQOperand_2: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t templ_arg_0 = va_arg(args, uint64_t);
		add_cs_detail_template_1(MI, op_group, op_num, templ_arg_0);
		return;
	}
	case ARM_OP_GROUP_ComplexRotationOp_180_90:
	case ARM_OP_GROUP_ComplexRotationOp_90_0: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t templ_arg_0 = va_arg(args, uint64_t);
		uint64_t templ_arg_1 = va_arg(args, uint64_t);
		add_cs_detail_template_2(MI, op_group, op_num, templ_arg_0,
					 templ_arg_1);
		return;
	}
	}
	unsigned op_num = va_arg(args, unsigned);
	add_cs_detail_general(MI, op_group, op_num);
}

static void insert_op(MCInst *MI, unsigned index, cs_arm_op op)
{
	if (!detail_is_set(MI)) {
		return;
	}
	ARM_check_safe_inc(MI);

	cs_arm_op *ops = ARM_get_detail(MI)->operands;
	int i = ARM_get_detail(MI)->op_count;
	if (index == -1) {
		ops[i] = op;
		ARM_inc_op_count(MI);
		return;
	}
	for (; i > 0 && i > index; --i) {
		ops[i] = ops[i - 1];
	}
	ops[index] = op;
	ARM_inc_op_count(MI);
}

/// Inserts a register to the detail operands at @index.
/// Already present operands are moved.
/// If @index is -1 the operand is appended.
void ARM_insert_detail_op_reg_at(MCInst *MI, unsigned index, arm_reg Reg,
				 cs_ac_type access)
{
	if (!detail_is_set(MI))
		return;

	cs_arm_op op;
	ARM_setup_op(&op);
	op.type = ARM_OP_REG;
	op.reg = Reg;
	op.access = access;
	insert_op(MI, index, op);
}

/// Inserts a immediate to the detail operands at @index.
/// Already present operands are moved.
/// If @index is -1 the operand is appended.
void ARM_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Val,
				 cs_ac_type access)
{
	if (!detail_is_set(MI))
		return;
	ARM_check_safe_inc(MI);

	cs_arm_op op;
	ARM_setup_op(&op);
	op.type = ARM_OP_IMM;
	op.imm = Val;
	op.access = access;

	insert_op(MI, index, op);
}

/// Adds a register ARM operand at position OpNum and increases the op_count by
/// one.
void ARM_set_detail_op_reg(MCInst *MI, unsigned OpNum, arm_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	ARM_check_safe_inc(MI);
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_REG);

	ARM_get_detail_op(MI, 0)->type = ARM_OP_REG;
	ARM_get_detail_op(MI, 0)->reg = Reg;
	ARM_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	ARM_inc_op_count(MI);
}

/// Adds an immediate ARM operand at position OpNum and increases the op_count
/// by one.
void ARM_set_detail_op_imm(MCInst *MI, unsigned OpNum, arm_op_type ImmType,
			   int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	ARM_check_safe_inc(MI);
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_IMM);
	CS_ASSERT_RET(ImmType == ARM_OP_IMM || ImmType == ARM_OP_PIMM ||
	       ImmType == ARM_OP_CIMM);

	ARM_get_detail_op(MI, 0)->type = ImmType;
	ARM_get_detail_op(MI, 0)->imm = Imm;
	ARM_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	ARM_inc_op_count(MI);
}

/// Adds the operand as to the previously added memory operand.
void ARM_set_detail_op_mem_offset(MCInst *MI, unsigned OpNum, uint64_t Val,
				  bool subtracted)
{
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) & CS_OP_MEM);

	if (!doing_mem(MI)) {
		CS_ASSERT_RET((ARM_get_detail_op(MI, -1) != NULL) &&
		       (ARM_get_detail_op(MI, -1)->type == ARM_OP_MEM));
		ARM_dec_op_count(MI);
	}

	if ((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM)
		ARM_set_detail_op_mem(MI, OpNum, false, 0, Val);
	else if ((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG)
		ARM_set_detail_op_mem(MI, OpNum, true, subtracted ? -1 : 1, Val);
	else
		CS_ASSERT_RET(0 && "Memory type incorrect.");
	ARM_get_detail_op(MI, 0)->subtracted = subtracted;

	if (!doing_mem(MI))
		ARM_inc_op_count(MI);
}

/// Adds a memory ARM operand at position OpNum. op_count is *not* increased by
/// one. This is done by ARM_set_mem_access().
void ARM_set_detail_op_mem(MCInst *MI, unsigned OpNum, bool is_index_reg,
			   int scale, uint64_t Val)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) & CS_OP_MEM);
	cs_op_type secondary_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;
	switch (secondary_type) {
	default:
		CS_ASSERT_RET(0 && "Secondary type not supported yet.");
	case CS_OP_REG: {
		CS_ASSERT_RET(secondary_type == CS_OP_REG);
		if (!is_index_reg) {
			ARM_get_detail_op(MI, 0)->mem.base = Val;
			if (MCInst_opIsTying(MI, OpNum) || MCInst_opIsTied(MI, OpNum)) {
				// Base registers can be writeback registers.
				// For this they tie an MC operand which has write
				// access. But this one is never processed in the printer
				// (because it is never emitted). Therefor it is never
				// added to the modified list.
				// Here we check for this case and add the memory register
				// to the modified list.
				map_add_implicit_write(MI, MCInst_getOpVal(MI, OpNum));
				MI->flat_insn->detail->writeback = true;
			} else {
				// If the base register is not tied, set the writebak flag to false.
				// Writeback for ARM only refers to the memory base register.
				// But other registers might be marked as tied as well.
				MI->flat_insn->detail->writeback = false;
			}
		} else {
			ARM_get_detail_op(MI, 0)->mem.index = Val;
		}
		ARM_get_detail_op(MI, 0)->mem.scale = scale;

		break;
	}
	case CS_OP_IMM: {
		CS_ASSERT_RET(secondary_type == CS_OP_IMM);
		if (((int32_t)Val) < 0)
			ARM_get_detail_op(MI, 0)->subtracted = true;
		ARM_get_detail_op(MI, 0)->mem.disp = ((int64_t)Val < 0) ? -Val :
									  Val;
		break;
	}
	}

	ARM_get_detail_op(MI, 0)->type = ARM_OP_MEM;
	ARM_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
}

/// Sets the neon_lane in the previous operand to the value of
/// MI->operands[OpNum] Decrements op_count by 1.
void ARM_set_detail_op_neon_lane(MCInst *MI, unsigned OpNum)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_IMM);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, OpNum));

	ARM_get_detail_op(MI, -1)->neon_lane = Val;
}

/// Adds a System Register and increments op_count by one.
/// @type ARM_OP_SYSREG, ARM_OP_BANKEDREG, ARM_OP_SYSM...
/// @p Mask is the MSR mask or UINT8_MAX if not set.
void ARM_set_detail_op_sysop(MCInst *MI, int Val, arm_op_type type,
			     bool IsOutReg, uint8_t Mask, uint16_t Sysm)
{
	if (!detail_is_set(MI))
		return;
	ARM_check_safe_inc(MI);

	ARM_get_detail_op(MI, 0)->type = type;
	switch (type) {
	default:
		CS_ASSERT_RET(0 && "Unknown system operand type.");
	case ARM_OP_SYSREG:
		ARM_get_detail_op(MI, 0)->sysop.reg.mclasssysreg = Val; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
		break;
	case ARM_OP_BANKEDREG:
		ARM_get_detail_op(MI, 0)->sysop.reg.bankedreg = Val;
		break;
	case ARM_OP_SPSR:
	case ARM_OP_CPSR:
		ARM_get_detail_op(MI, 0)->reg =
			type == ARM_OP_SPSR ? ARM_REG_SPSR : ARM_REG_CPSR;
		ARM_get_detail_op(MI, 0)->sysop.psr_bits = Val; // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
		break;
	}
	ARM_get_detail_op(MI, 0)->sysop.sysm = Sysm;
	ARM_get_detail_op(MI, 0)->sysop.msr_mask = Mask;
	ARM_get_detail_op(MI, 0)->access = IsOutReg ? CS_AC_WRITE : CS_AC_READ;
	ARM_inc_op_count(MI);
}

/// Transforms the immediate of the operand to a float and stores it.
/// Increments the op_counter by one.
void ARM_set_detail_op_float(MCInst *MI, unsigned OpNum, uint64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	ARM_check_safe_inc(MI);

	ARM_get_detail_op(MI, 0)->type = ARM_OP_FP;
	ARM_get_detail_op(MI, 0)->fp = ARM_AM_getFPImmFloat(Imm);
	ARM_inc_op_count(MI);
}

#endif
