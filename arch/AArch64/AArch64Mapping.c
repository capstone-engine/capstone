/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_AARCH64

#include <stdio.h>	// debug
#include <string.h>

#include "capstone/aarch64.h"

#include "../../cs_simple_types.h"
#include "../../Mapping.h"
#include "../../MathExtras.h"
#include "../../utils.h"

#include "AArch64AddressingModes.h"
#include "AArch64BaseInfo.h"
#include "AArch64DisassemblerExtension.h"
#include "AArch64Linkage.h"
#include "AArch64Mapping.h"

#ifndef CAPSTONE_DIET
static aarch64_reg aarch64_flag_regs[] = {
	AArch64_REG_NZCV,
};

static aarch64_sysreg aarch64_flag_sys_regs[] = {
	AArch64_SYSREG_NZCV,
	AArch64_SYSREG_PMOVSCLR_EL0,
	AArch64_SYSREG_PMOVSSET_EL0,
	AArch64_SYSREG_SPMOVSCLR_EL0,
	AArch64_SYSREG_SPMOVSSET_EL0
};
#endif // CAPSTONE_DIET

static AArch64Layout_VectorLayout sme_reg_to_vas(aarch64_reg reg) {
	switch (reg) {
	default:
		return AArch64Layout_Invalid;
	case AArch64_REG_ZAB0:
		return AArch64Layout_VL_B;
	case AArch64_REG_ZAH0:
	case AArch64_REG_ZAH1:
		return AArch64Layout_VL_H;
	case AArch64_REG_ZAS0:
	case AArch64_REG_ZAS1:
	case AArch64_REG_ZAS2:
	case AArch64_REG_ZAS3:
		return AArch64Layout_VL_S;
	case AArch64_REG_ZAD0:
	case AArch64_REG_ZAD1:
	case AArch64_REG_ZAD2:
	case AArch64_REG_ZAD3:
	case AArch64_REG_ZAD4:
	case AArch64_REG_ZAD5:
	case AArch64_REG_ZAD6:
	case AArch64_REG_ZAD7:
		return AArch64Layout_VL_D;
	case AArch64_REG_ZAQ0:
	case AArch64_REG_ZAQ1:
	case AArch64_REG_ZAQ2:
	case AArch64_REG_ZAQ3:
	case AArch64_REG_ZAQ4:
	case AArch64_REG_ZAQ5:
	case AArch64_REG_ZAQ6:
	case AArch64_REG_ZAQ7:
	case AArch64_REG_ZAQ8:
	case AArch64_REG_ZAQ9:
	case AArch64_REG_ZAQ10:
	case AArch64_REG_ZAQ11:
	case AArch64_REG_ZAQ12:
	case AArch64_REG_ZAQ13:
	case AArch64_REG_ZAQ14:
	case AArch64_REG_ZAQ15:
		return AArch64Layout_VL_Q;
	case AArch64_REG_ZA:
		return AArch64Layout_VL_Complete;
	}
}

void AArch64_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, AArch64RegDesc, AArch64_REG_ENDING, 0, 0, AArch64MCRegisterClasses,
		ARR_SIZE(AArch64MCRegisterClasses), 0, 0,
		AArch64RegDiffLists, 0, AArch64SubRegIdxLists, ARR_SIZE(AArch64SubRegIdxLists), 0);
}

const insn_map aarch64_insns[] = {
#include "AArch64GenCSMappingInsn.inc"
};

static const name_map insn_alias_mnem_map[] = {
#include "AArch64GenCSAliasMnemMap.inc"
	{ AArch64_INS_ALIAS_CFP, "cfp" },
	{ AArch64_INS_ALIAS_DVP, "dvp" },
	{ AArch64_INS_ALIAS_COSP, "cosp" },
	{ AArch64_INS_ALIAS_CPP, "cpp" },
	{ AArch64_INS_ALIAS_IC, "ic" },
	{ AArch64_INS_ALIAS_DC, "dc" },
	{ AArch64_INS_ALIAS_AT, "at" },
	{ AArch64_INS_ALIAS_TLBI, "tlbi" },
	{ AArch64_INS_ALIAS_TLBIP, "tlbip" },
	{ AArch64_INS_ALIAS_RPRFM, "rprfm" },
	{ AArch64_INS_ALIAS_LSL, "lsl" },
	{ AArch64_INS_ALIAS_SBFX, "sbfx" },
	{ AArch64_INS_ALIAS_UBFX, "ubfx" },
	{ AArch64_INS_ALIAS_SBFIZ, "sbfiz" },
	{ AArch64_INS_ALIAS_UBFIZ, "ubfiz" },
	{ AArch64_INS_ALIAS_BFC, "bfc" },
	{ AArch64_INS_ALIAS_BFI, "bfi" },
	{ AArch64_INS_ALIAS_BFXIL, "bfxil" },
	{ AArch64_INS_ALIAS_END, NULL },
};

static const char *get_custom_reg_alias(unsigned reg)
{
	switch (reg) {
	case AArch64_REG_X29:
		return "fp";
	case AArch64_REG_X30:
		return "lr";
	}
	return NULL;
}

/// Very annoyingly LLVM hard codes the vector layout post-fixes into the asm string.
/// In this function we check for these cases and add the vectorlayout/arrangement
/// specifier.
void AArch64_add_vas(MCInst *MI, const SStream *OS) {
	if (!detail_is_set(MI)) {
		return;
	}

	if (AArch64_get_detail(MI)->op_count == 0) {
		return;
	}

	// Search for r".[0-9]{1,2}[bhsdq]\W"
	// with poor mans regex
	const char *vl_ptr = strchr(OS->buffer, '.');
	while (vl_ptr) {
		// Number after dot?
		unsigned num = 0;
		if (strchr("1248", vl_ptr[1])) {
			num = atoi(vl_ptr + 1);
			vl_ptr = num > 9 ? vl_ptr + 3 : vl_ptr + 2;
		} else {
			vl_ptr++;
		}

		// Layout letter
		char letter = '\0';
		if (strchr("bhsdq", vl_ptr[0])) {
			letter = vl_ptr[0];
		}
		if (!letter) {
			goto next_dot_continue;
		}

		AArch64Layout_VectorLayout vl = AArch64Layout_Invalid;
		switch (letter) {
		default:
			assert(0 && "Unhandled vector layout letter.");
			return;
		case 'b':
			vl = AArch64Layout_VL_B;
			break;
		case 'h':
			vl = AArch64Layout_VL_H;
			break;
		case 's':
			vl = AArch64Layout_VL_S;
			break;
		case 'd':
			vl = AArch64Layout_VL_D;
			break;
		case 'q':
			vl = AArch64Layout_VL_Q;
			break;
		}
		vl |= (num << 8);

		// Determine op index by searching for trainling commata after op string
		uint32_t op_idx = 0;
		const char *comma_ptr = strchr(OS->buffer, ',');;
		while (comma_ptr && comma_ptr < vl_ptr) {
			++op_idx;
			comma_ptr = strchr(comma_ptr + 1, ',');
		}
		if (!comma_ptr) {
			// Last op doesn't have a trailing commata.
			op_idx = AArch64_get_detail(MI)->op_count - 1;
		}
		if (op_idx >= AArch64_get_detail(MI)->op_count) {
			// A memory operand with a commata in [base, dist]
			op_idx = AArch64_get_detail(MI)->op_count - 1;
		}

		// Search for the operand this one belongs to.
		cs_aarch64_op *op = &AArch64_get_detail(MI)->operands[op_idx];
		if ((op->type != AArch64_OP_REG && op->type != AArch64_OP_SME_MATRIX) || op->vas != AArch64Layout_Invalid) {
			goto next_dot_continue;
		}
		op->vas = vl;

next_dot_continue:
		vl_ptr = strchr(vl_ptr + 1, '.');
	}
}

const char *AArch64_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;
	const char *alias = get_custom_reg_alias(reg);
	if ((syntax_opt & CS_OPT_SYNTAX_CS_REG_ALIAS) && alias)
		return alias;

	if (((cs_struct *)(uintptr_t)handle)->syntax & CS_OPT_SYNTAX_NOREGNAME) {
		return AArch64_LLVM_getRegisterName(reg, AArch64_NoRegAltName);
	}
	// TODO Add options for the other register names
	return AArch64_LLVM_getRegisterName(reg, AArch64_NoRegAltName);
}

void AArch64_setup_op(cs_aarch64_op *op)
{
	memset(op, 0, sizeof(cs_aarch64_op));
	op->type = AArch64_OP_INVALID;
	op->vector_index = -1;
}

void AArch64_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		memset(get_detail(MI), 0,
			   offsetof(cs_detail, aarch64) + sizeof(cs_aarch64));
		for (int i = 0; i < ARR_SIZE(AArch64_get_detail(MI)->operands); i++)
			AArch64_setup_op(&AArch64_get_detail(MI)->operands[i]);
		AArch64_get_detail(MI)->cc = AArch64CC_Invalid;
	}
}

/// Unfortunately, the AArch64 definitions do not indicate in any way
/// (exception are the instruction identifiers), if memory accesses
/// is post- or pre-indexed.
/// So the only generic way to determine, if the memory access is in
/// post-indexed addressing mode, is by search for "<membase>], #<memdisp>" in
/// @p OS.
/// Searching the asm string to determine such a property is enormously ugly
/// and wastes resources.
/// Sorry, I know and do feel bad about it. But for now it works.
static bool AArch64_check_post_index_am(const MCInst *MI, const SStream *OS) {
	if (AArch64_get_detail(MI)->post_index) {
		return true;
	}
	cs_aarch64_op *memop = NULL;
	for (int i = 0; i < AArch64_get_detail(MI)->op_count; ++i) {
		if (AArch64_get_detail(MI)->operands[i].type & CS_OP_MEM) {
			memop = &AArch64_get_detail(MI)->operands[i];
			break;
		}
	}
	if (!memop)
		return false;

	const char *membase = AArch64_LLVM_getRegisterName(memop->mem.base, AArch64_NoRegAltName);
	int64_t memdisp = memop->mem.disp;
	SStream pattern = { 0 };
	SStream_concat(&pattern, membase);
	SStream_concat(&pattern, "], ");
	printInt32Bang(&pattern, memdisp);
	return strstr(OS->buffer, pattern.buffer) != NULL;
}

static void AArch64_check_updates_flags(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI))
		return;
	cs_detail *detail = get_detail(MI);
	// Implicitly written registers
	for (int i = 0; i < detail->regs_write_count; ++i) {
		if (detail->regs_write[i] == 0)
			break;
		for (int j = 0; j < ARR_SIZE(aarch64_flag_regs); ++j) {
			if (detail->regs_write[i] == aarch64_flag_regs[j]) {
				detail->aarch64.update_flags = true;
				return;
			}
		}
	}
	for (int i = 0; i < detail->aarch64.op_count; ++i) {
		if (detail->aarch64.operands[i].type == AArch64_OP_SYSREG &&
			detail->aarch64.operands[i].sysop.sub_type == AArch64_OP_REG_MSR) {
			for (int j = 0; j < ARR_SIZE(aarch64_flag_sys_regs); ++j)
				if (detail->aarch64.operands[i].sysop.reg.sysreg == aarch64_flag_sys_regs[j]) {
					detail->aarch64.update_flags = true;
					return;
				}
		} else if (detail->aarch64.operands[i].type == AArch64_OP_REG &&
				detail->aarch64.operands[i].access & CS_AC_WRITE) {
			for (int j = 0; j < ARR_SIZE(aarch64_flag_regs); ++j)
				if (detail->aarch64.operands[i].reg == aarch64_flag_regs[j]) {
					detail->aarch64.update_flags = true;
					return;
				}
		}
	}
#endif // CAPSTONE_DIET
}

static void add_non_alias_details(MCInst *MI) {
	unsigned Opcode = MCInst_getOpcode(MI);
	switch (Opcode) {
	default:
		break;
	case AArch64_FCMPDri:
	case AArch64_FCMPEDri:
	case AArch64_FCMPEHri:
	case AArch64_FCMPESri:
	case AArch64_FCMPHri:
	case AArch64_FCMPSri:
		AArch64_insert_detail_op_reg_at(MI, -1, AArch64_REG_XZR, CS_AC_READ);
		break;
	case AArch64_CMEQv16i8rz:
	case AArch64_CMEQv1i64rz:
	case AArch64_CMEQv2i32rz:
	case AArch64_CMEQv2i64rz:
	case AArch64_CMEQv4i16rz:
	case AArch64_CMEQv4i32rz:
	case AArch64_CMEQv8i16rz:
	case AArch64_CMEQv8i8rz:
	case AArch64_CMGEv16i8rz:
	case AArch64_CMGEv1i64rz:
	case AArch64_CMGEv2i32rz:
	case AArch64_CMGEv2i64rz:
	case AArch64_CMGEv4i16rz:
	case AArch64_CMGEv4i32rz:
	case AArch64_CMGEv8i16rz:
	case AArch64_CMGEv8i8rz:
	case AArch64_CMGTv16i8rz:
	case AArch64_CMGTv1i64rz:
	case AArch64_CMGTv2i32rz:
	case AArch64_CMGTv2i64rz:
	case AArch64_CMGTv4i16rz:
	case AArch64_CMGTv4i32rz:
	case AArch64_CMGTv8i16rz:
	case AArch64_CMGTv8i8rz:
	case AArch64_CMLEv16i8rz:
	case AArch64_CMLEv1i64rz:
	case AArch64_CMLEv2i32rz:
	case AArch64_CMLEv2i64rz:
	case AArch64_CMLEv4i16rz:
	case AArch64_CMLEv4i32rz:
	case AArch64_CMLEv8i16rz:
	case AArch64_CMLEv8i8rz:
	case AArch64_CMLTv16i8rz:
	case AArch64_CMLTv1i64rz:
	case AArch64_CMLTv2i32rz:
	case AArch64_CMLTv2i64rz:
	case AArch64_CMLTv4i16rz:
	case AArch64_CMLTv4i32rz:
	case AArch64_CMLTv8i16rz:
	case AArch64_CMLTv8i8rz:
		AArch64_insert_detail_op_imm_at(MI, -1, 0);
		break;
	case AArch64_FCMEQv1i16rz:
	case AArch64_FCMEQv1i32rz:
	case AArch64_FCMEQv1i64rz:
	case AArch64_FCMEQv2i32rz:
	case AArch64_FCMEQv2i64rz:
	case AArch64_FCMEQv4i16rz:
	case AArch64_FCMEQv4i32rz:
	case AArch64_FCMEQv8i16rz:
	case AArch64_FCMGEv1i16rz:
	case AArch64_FCMGEv1i32rz:
	case AArch64_FCMGEv2i32rz:
	case AArch64_FCMGEv2i64rz:
	case AArch64_FCMGEv4i16rz:
	case AArch64_FCMGEv4i32rz:
	case AArch64_FCMGEv8i16rz:
	case AArch64_FCMGTv2i32rz:
	case AArch64_FCMGTv2i64rz:
	case AArch64_FCMGTv4i16rz:
	case AArch64_FCMGTv4i32rz:
	case AArch64_FCMGTv8i16rz:
	case AArch64_FCMLEv2i32rz:
	case AArch64_FCMLEv2i64rz:
	case AArch64_FCMLEv4i16rz:
	case AArch64_FCMLEv4i32rz:
	case AArch64_FCMLEv8i16rz:
	case AArch64_FCMEQ_PPzZ0_D:
	case AArch64_FCMEQ_PPzZ0_H:
	case AArch64_FCMEQ_PPzZ0_S:
	case AArch64_FCMGE_PPzZ0_D:
	case AArch64_FCMGE_PPzZ0_H:
	case AArch64_FCMGE_PPzZ0_S:
	case AArch64_FCMGT_PPzZ0_D:
	case AArch64_FCMGT_PPzZ0_H:
	case AArch64_FCMGT_PPzZ0_S:
	case AArch64_FCMLE_PPzZ0_D:
	case AArch64_FCMLE_PPzZ0_H:
	case AArch64_FCMLE_PPzZ0_S:
	case AArch64_FCMLT_PPzZ0_D:
	case AArch64_FCMLT_PPzZ0_H:
	case AArch64_FCMLT_PPzZ0_S:
	case AArch64_FCMNE_PPzZ0_D:
	case AArch64_FCMNE_PPzZ0_H:
	case AArch64_FCMNE_PPzZ0_S:
	case AArch64_FCMLTv2i32rz:
	case AArch64_FCMLTv2i64rz:
	case AArch64_FCMLTv4i16rz:
	case AArch64_FCMLTv4i32rz:
	case AArch64_FCMLTv8i16rz:
		AArch64_insert_detail_op_float_at(MI, -1, 0.0f, CS_AC_READ);
		break;
	}
}

static void AArch64_add_not_defined_ops(MCInst *MI, const SStream *OS)
{
	if (!detail_is_set(MI))
		return;

	if (!MI->flat_insn->is_alias || !MI->flat_insn->usesAliasDetails) {
		add_non_alias_details(MI);
		return;
	}

	// Alias details
	switch(MI->flat_insn->alias_id) {
	default:
		return;
	case AArch64_INS_ALIAS_FMOV:
		AArch64_insert_detail_op_float_at(MI, -1, 0.0f, CS_AC_READ);
		break;
	case AArch64_INS_ALIAS_LD1:
	case AArch64_INS_ALIAS_LD1R:
	case AArch64_INS_ALIAS_LD2:
	case AArch64_INS_ALIAS_LD2R:
	case AArch64_INS_ALIAS_LD3:
	case AArch64_INS_ALIAS_LD3R:
	case AArch64_INS_ALIAS_LD4:
	case AArch64_INS_ALIAS_LD4R:
	case AArch64_INS_ALIAS_ST1:
	case AArch64_INS_ALIAS_ST2:
	case AArch64_INS_ALIAS_ST3:
	case AArch64_INS_ALIAS_ST4: {
		// Add post-index disp
		const char *disp_off = strrchr(OS->buffer, '#');
		if (!disp_off)
			return;
		unsigned disp = atoi(disp_off + 1);
		AArch64_get_detail_op(MI, -1)->type = AArch64_OP_MEM;
		AArch64_get_detail_op(MI, -1)->mem.base = AArch64_get_detail_op(MI, -1)->reg;
		AArch64_get_detail_op(MI, -1)->mem.disp = disp;
		AArch64_get_detail(MI)->post_index = true;
		break;
	}
	}
}

void AArch64_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, aarch64_insns, ARR_SIZE(aarch64_insns));
	map_implicit_reads(MI, aarch64_insns);
	map_implicit_writes(MI, aarch64_insns);
	map_groups(MI, aarch64_insns);
}

bool AArch64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
						MCInst *MI, uint16_t *size, uint64_t address,
						void *info) {
	AArch64_init_cs_detail(MI);
	bool Result = AArch64_LLVM_getInstruction(handle, code, code_len, MI, size, address,
								 info) != MCDisassembler_Fail;
	AArch64_set_instr_map_data(MI);
	return Result;
}

/// Patches the register names with Capstone specific alias.
/// Those are common alias for registers (e.g. r15 = pc)
/// which are not set in LLVM.
static void patch_cs_reg_alias(char *asm_str)
{
	bool skip_sub = false;
	char *x29 = strstr(asm_str, "x29");
	if (x29 > asm_str && strstr(asm_str, "0x29") == (x29 - 1)) {
		// Check for hex prefix
		skip_sub = true;
	}
	while (x29 && !skip_sub) {
		x29[0] = 'f';
		x29[1] = 'p';
		memmove(x29 + 2, x29 + 3, strlen(x29 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		x29 = strstr(asm_str, "x29");
	}
	skip_sub = false;
	char *x30 = strstr(asm_str, "x30");
	if (x30 > asm_str && strstr(asm_str, "0x30") == (x30 - 1)) {
		// Check for hex prefix
		skip_sub = true;
	}
	while (x30 && !skip_sub) {
		x30[0] = 'l';
		x30[1] = 'r';
		memmove(x30 + 2, x30 + 3, strlen(x30 + 3));
		asm_str[strlen(asm_str) - 1] = '\0';
		x30 = strstr(asm_str, "x30");
	}
}

/// Adds group to the instruction which are not defined in LLVM.
static void AArch64_add_cs_groups(MCInst *MI)
{
	unsigned Opcode = MI->flat_insn->id;
	switch (Opcode) {
	default:
		return;
	case AArch64_INS_SVC:
		add_group(MI, AArch64_GRP_INT);
		break;
	case AArch64_INS_SMC:
	case AArch64_INS_MSR:
	case AArch64_INS_MRS:
		add_group(MI, AArch64_GRP_PRIVILEGE);
		break;
	case AArch64_INS_RET:
	case AArch64_INS_RETAA:
	case AArch64_INS_RETAB:
		add_group(MI, AArch64_GRP_RET);
		break;
	}
}

void AArch64_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info) {
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	MI->fillDetailOps = detail_is_set(MI);
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	AArch64_LLVM_printInstruction(MI, O, info);
	if (detail_is_set(MI))
		AArch64_get_detail(MI)->post_index = AArch64_check_post_index_am(MI, O);
	AArch64_check_updates_flags(MI);
	map_set_alias_id(MI, O, insn_alias_mnem_map, ARR_SIZE(insn_alias_mnem_map) - 1);
	int syntax_opt = MI->csh->syntax;
	if (syntax_opt & CS_OPT_SYNTAX_CS_REG_ALIAS)
		patch_cs_reg_alias(O->buffer);
	AArch64_add_not_defined_ops(MI, O);
	AArch64_add_cs_groups(MI);
	AArch64_add_vas(MI, O);
}

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Done after disassembly
	return;
}

static const char *const insn_name_maps[] = {
#include "AArch64GenCSMappingInsnName.inc"
};

const char *AArch64_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < AArch64_INS_ALIAS_END && id > AArch64_INS_ALIAS_BEGIN) {
		if (id - AArch64_INS_ALIAS_BEGIN >= ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - AArch64_INS_ALIAS_BEGIN - 1].name;
	}
	if (id >= AArch64_INS_ENDING)
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
	{ AArch64_GRP_INVALID, NULL },
	{ AArch64_GRP_JUMP, "jump" },
	{ AArch64_GRP_CALL, "call" },
	{ AArch64_GRP_RET, "return" },
	{ AArch64_GRP_PRIVILEGE, "privilege" },
	{ AArch64_GRP_INT, "int" },
	{ AArch64_GRP_BRANCH_RELATIVE, "branch_relative" },

	// architecture-specific groups
	#include "AArch64GenCSFeatureName.inc"
};
#endif

const char *AArch64_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
aarch64_insn AArch64_map_insn(const char *name)
{
	unsigned int i;

	for(i = 1; i < ARR_SIZE(insn_name_maps); i++) {
		if (!strcmp(name, insn_name_maps[i]))
			return i;
	}

	// not found
	return AArch64_INS_INVALID;
}

#ifndef CAPSTONE_DIET

static const map_insn_ops insn_operands[] = {
#include "AArch64GenCSMappingInsnOp.inc"
};

void AArch64_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_aarch64 *aarch64 = &(insn->detail->aarch64);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read, read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write, write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < aarch64->op_count; i++) {
		cs_aarch64_op *op = &(aarch64->operands[i]);
		switch((int)op->type) {
			case AArch64_OP_REG:
				if ((op->access & CS_AC_READ) && !arr_exist(regs_read, read_count, op->reg)) {
					regs_read[read_count] = (uint16_t)op->reg;
					read_count++;
				}
				if ((op->access & CS_AC_WRITE) && !arr_exist(regs_write, write_count, op->reg)) {
					regs_write[write_count] = (uint16_t)op->reg;
					write_count++;
				}
				break;
			case AArch64_OP_MEM:
				// registers appeared in memory references always being read
				if ((op->mem.base != AArch64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != AArch64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((insn->detail->writeback) && (op->mem.base != AArch64_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
					regs_write[write_count] = (uint16_t)op->mem.base;
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

static AArch64Layout_VectorLayout get_vl_by_suffix(const char suffix) {
	switch (suffix) {
	default:
		return AArch64Layout_Invalid;
	case 'b':
	case 'B':
		return AArch64Layout_VL_B;
	case 'h':
	case 'H':
		return AArch64Layout_VL_H;
	case 's':
	case 'S':
		return AArch64Layout_VL_S;
	case 'd':
	case 'D':
		return AArch64Layout_VL_D;
	case 'q':
	case 'Q':
		return AArch64Layout_VL_Q;
	}
}

static unsigned get_vec_list_num_regs(MCInst *MI, unsigned Reg) {
	// Work out how many registers there are in the list (if there is an actual
	// list).
	unsigned NumRegs = 1;
	if (MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_DDRegClassID), Reg) ||
		MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR2RegClassID),
			Reg) ||
		MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_QQRegClassID), Reg) ||
		MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_PPR2RegClassID),
			Reg) ||
		MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR2StridedRegClassID),
			Reg))
		NumRegs = 2;
	else if (MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_DDDRegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR3RegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_QQQRegClassID),
				 Reg))
		NumRegs = 3;
	else if (MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_DDDDRegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR4RegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_QQQQRegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI,
											 AArch64_ZPR4StridedRegClassID),
				 Reg))
		NumRegs = 4;
	return NumRegs;
}

static unsigned get_vec_list_stride(MCInst *MI, unsigned Reg) {
	unsigned Stride = 1;
	if (MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR2StridedRegClassID),
			Reg))
		Stride = 8;
	else if (MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI,
											 AArch64_ZPR4StridedRegClassID),
				 Reg))
		Stride = 4;
	return Stride;
}

static unsigned get_vec_list_first_reg(MCInst *MI, unsigned RegL) {
	unsigned Reg = RegL;
	// Now forget about the list and find out what the first register is.
	if (MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_dsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_dsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_qsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_qsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_zsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_zsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_psub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, RegL, AArch64_psub0);

	// If it's a D-reg, we need to promote it to the equivalent Q-reg before
	// printing (otherwise getRegisterName fails).
	if (MCRegisterClass_contains(
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_FPR64RegClassID),
			Reg)) {
		const MCRegisterClass *FPR128RC =
			MCRegisterInfo_getRegClass(MI->MRI, AArch64_FPR128RegClassID);
		Reg = MCRegisterInfo_getMatchingSuperReg(MI->MRI, Reg, AArch64_dsub,
									 FPR128RC);
	}
	return Reg;
}

static bool is_vector_reg(unsigned Reg) {
	if ((Reg >= AArch64_Q0) && (Reg <= AArch64_Q31))
		return true;
	else if ((Reg >= AArch64_Z0) && (Reg <= AArch64_Z31))
		return true;
	else if ((Reg >= AArch64_P0) && (Reg <= AArch64_P15))
		return true;
	return false;
}

static unsigned getNextVectorRegister(unsigned Reg, unsigned Stride /* = 1 */)
{
	while (Stride--) {
		if (!is_vector_reg(Reg)) {
			assert(0 && "Vector register expected!");
			return 0;
		}
		// Vector lists can wrap around.
		else if (Reg == AArch64_Q31)
			Reg = AArch64_Q0;
		// Vector lists can wrap around.
		else if (Reg == AArch64_Z31)
			Reg = AArch64_Z0;
		// Vector lists can wrap around.
		else if (Reg == AArch64_P15)
			Reg = AArch64_P0;
		else
			// Assume ordered registers
			++Reg;
	}
	return Reg;
}

static aarch64_extender llvm_to_cs_ext(AArch64_AM_ShiftExtendType ExtType) {
	switch(ExtType) {
	default:
		return AArch64_EXT_INVALID;
	case AArch64_AM_UXTB:
		return AArch64_EXT_UXTB;
	case AArch64_AM_UXTH:
		return AArch64_EXT_UXTH;
	case AArch64_AM_UXTW:
		return AArch64_EXT_UXTW;
	case AArch64_AM_UXTX:
		return AArch64_EXT_UXTX;
	case AArch64_AM_SXTB:
		return AArch64_EXT_SXTB;
	case AArch64_AM_SXTH:
		return AArch64_EXT_SXTH;
	case AArch64_AM_SXTW:
		return AArch64_EXT_SXTW;
	case AArch64_AM_SXTX:
		return AArch64_EXT_SXTX;
	}
}

static aarch64_shifter llvm_to_cs_shift(AArch64_AM_ShiftExtendType ShiftExtType) {
	switch(ShiftExtType) {
	default:
		return AArch64_SFT_INVALID;
	case AArch64_AM_LSL:
		return AArch64_SFT_LSL;
	case AArch64_AM_LSR:
		return AArch64_SFT_LSR;
	case AArch64_AM_ASR:
		return AArch64_SFT_ASR;
	case AArch64_AM_ROR:
		return AArch64_SFT_ROR;
	case AArch64_AM_MSL:
		return AArch64_SFT_MSL;
	}
}

/// Initializes or finishes a memory operand of Capstone (depending on \p
/// status). A memory operand in Capstone can be assembled by two LLVM operands.
/// E.g. the base register and the immediate disponent.
void AArch64_set_mem_access(MCInst *MI, bool status)
{
	if (!detail_is_set(MI))
		return;
	set_doing_mem(MI, status);
	if (status) {
		if (AArch64_get_detail(MI)->op_count > 0 &&
			AArch64_get_detail_op(MI, -1)->type == AArch64_OP_MEM &&
			AArch64_get_detail_op(MI, -1)->mem.index == AArch64_REG_INVALID &&
			AArch64_get_detail_op(MI, -1)->mem.disp == 0) {
			// Previous memory operand not done yet. Select it.
			AArch64_dec_op_count(MI);
			return;
		}

		// Init a new one.
		AArch64_get_detail_op(MI, 0)->type = AArch64_OP_MEM;
		AArch64_get_detail_op(MI, 0)->mem.base = AArch64_REG_INVALID;
		AArch64_get_detail_op(MI, 0)->mem.index = AArch64_REG_INVALID;
		AArch64_get_detail_op(MI, 0)->mem.disp = 0;

#ifndef CAPSTONE_DIET
		uint8_t access =
			map_get_op_access(MI, AArch64_get_detail(MI)->op_count);
		AArch64_get_detail_op(MI, 0)->access = access;
#endif
	} else {
		// done, select the next operand slot
		AArch64_inc_op_count(MI);
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function has no
/// specialities.
static void add_cs_detail_general(MCInst *MI, aarch64_op_group op_group,
								  unsigned OpNum) {
	if (!detail_is_set(MI))
		return;

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case AArch64_OP_GROUP_Operand: {
		cs_op_type primary_op_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;
		switch (primary_op_type) {
		default:
			printf("Unhandled operand type 0x%x\n", primary_op_type);
			assert(0);
		case AArch64_OP_REG:
			AArch64_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
			break;
		case AArch64_OP_IMM:
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM,
						MCInst_getOpVal(MI, OpNum));
			break;
		case AArch64_OP_FP: {
			// printOperand does not handle FP operands. But sometimes
			// is used to print FP operands as normal immediate.
			AArch64_get_detail_op(MI, 0)->type = AArch64_OP_IMM;
			AArch64_get_detail_op(MI, 0)->imm = MCInst_getOpVal(MI, OpNum);
			AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
			AArch64_inc_op_count(MI);
			break;
		}
		}
		break;
	}
	case AArch64_OP_GROUP_AddSubImm: {
		unsigned Val = (MCInst_getOpVal(MI, OpNum) & 0xfff);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		// Shift is added in printShifter()
		break;
	}
	case AArch64_OP_GROUP_AdrLabel: {
		int64_t Offset = MCInst_getOpVal(MI, OpNum);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, (MI->address & -4) + Offset);
		break;
	}
	case AArch64_OP_GROUP_AdrpLabel: {
		int64_t Offset = MCInst_getOpVal(MI, OpNum) * 4096;
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, (MI->address & -4096) + Offset);
		break;
	}
	case AArch64_OP_GROUP_AlignedLabel: {
		int64_t Offset = MCInst_getOpVal(MI, OpNum) * 4;
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, MI->address + Offset);
		break;
	}
	case AArch64_OP_GROUP_AMNoIndex: {
		AArch64_set_detail_op_mem(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_ArithExtend: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		AArch64_AM_ShiftExtendType ExtType = AArch64_AM_getArithExtendType(Val);
		unsigned ShiftVal = AArch64_AM_getArithShiftValue(Val);

		AArch64_get_detail_op(MI, -1)->ext = llvm_to_cs_ext(ExtType);
		AArch64_get_detail_op(MI, -1)->shift.value = ShiftVal;
		AArch64_get_detail_op(MI, -1)->shift.type = AArch64_SFT_LSL;
		break;
	}
	case AArch64_OP_GROUP_BarriernXSOption: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		aarch64_sysop sysop;
		const AArch64DBnXS_DBnXS *DB = AArch64DBnXS_lookupDBnXSByEncoding(Val);
        if (DB)
            sysop.imm = DB->SysImm;
        else
            sysop.imm.raw_val = Val;
		sysop.sub_type = AArch64_OP_DBNXS;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSIMM);
		break;
	}
	case AArch64_OP_GROUP_BarrierOption: {
		unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, OpNum));
		unsigned Opcode = MCInst_getOpcode(MI);
		aarch64_sysop sysop;

		if (Opcode == AArch64_ISB) {
			const AArch64ISB_ISB *ISB = AArch64ISB_lookupISBByEncoding(Val);
            if (ISB)
                sysop.alias = ISB->SysAlias;
            else
                sysop.alias.raw_val = Val;
			sysop.sub_type = AArch64_OP_ISB;
			AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		} else if (Opcode == AArch64_TSB) {
			const AArch64TSB_TSB *TSB = AArch64TSB_lookupTSBByEncoding(Val);
            if (TSB)
                sysop.alias = TSB->SysAlias;
            else
                sysop.alias.raw_val = Val;
			sysop.sub_type = AArch64_OP_TSB;
			AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		} else {
			const AArch64DB_DB *DB = AArch64DB_lookupDBByEncoding(Val);
            if (DB)
                sysop.alias = DB->SysAlias;
            else
                sysop.alias.raw_val = Val;
			sysop.sub_type = AArch64_OP_DB;
			AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		}
		break;
	}
	case AArch64_OP_GROUP_BTIHintOp: {
		aarch64_sysop sysop;
		unsigned btihintop = MCInst_getOpVal(MI, OpNum) ^ 32;
		const AArch64BTIHint_BTI *BTI = AArch64BTIHint_lookupBTIByEncoding(btihintop);
        if (BTI)
            sysop.alias = BTI->SysAlias;
        else
            sysop.alias.raw_val = btihintop;
		sysop.sub_type = AArch64_OP_BTI;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_CondCode: {
		AArch64_get_detail(MI)->cc = MCInst_getOpVal(MI, OpNum);
		break;
	}
	case AArch64_OP_GROUP_ExtendedRegister: {
		AArch64_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_FPImmOperand: {
		MCOperand *MO = MCInst_getOperand(MI, (OpNum));
		float FPImm = MCOperand_isDFPImm(MO)
						  ? BitsToDouble(MCOperand_getImm(MO))
						  : AArch64_AM_getFPImmFloat(MCOperand_getImm(MO));
		AArch64_set_detail_op_float(MI, OpNum, FPImm);
		break;
	}
	case AArch64_OP_GROUP_GPR64as32: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		AArch64_set_detail_op_reg(MI, OpNum, getWRegFromXReg(Reg));
		break;
	}
	case AArch64_OP_GROUP_GPR64x8: {
		unsigned Reg = MCInst_getOpVal(MI, (OpNum));
		Reg = MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_x8sub_0);
		AArch64_set_detail_op_reg(MI, OpNum, Reg);
		break;
	}
	case AArch64_OP_GROUP_Imm:
	case AArch64_OP_GROUP_ImmHex:
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, MCInst_getOpVal(MI, OpNum));
		break;
	case AArch64_OP_GROUP_ImplicitlyTypedVectorList:
		// The TypedVectorList implements the logic of implicitly typed operand.
		add_cs_detail(MI, AArch64_OP_GROUP_TypedVectorList_0_b, OpNum, 0, 0);
		break;
	case AArch64_OP_GROUP_InverseCondCode: {
		AArch64CC_CondCode CC =
			(AArch64CC_CondCode)MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		AArch64_get_detail(MI)->cc = AArch64CC_getInvertedCondCode(CC);
		break;
	}
	case AArch64_OP_GROUP_MatrixIndex: {
		assert(AArch64_get_detail(MI)->op_count >= 1);
		if (AArch64_get_detail_op(MI, -1)->type == AArch64_OP_SME_MATRIX)
			// The index is part of an SME matrix
			AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_SLICE_OFF, AArch64Layout_Invalid);
		else
			// The index is used for an SVE2 instruction.
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, MCInst_getOpVal(MI, OpNum));

		break;
	}
	case AArch64_OP_GROUP_MatrixTile: {
		const char *RegName = AArch64_LLVM_getRegisterName(MCInst_getOpVal(MI, OpNum), AArch64_NoRegAltName);
		const char *Dot = strstr(RegName, ".");
		AArch64Layout_VectorLayout vas = AArch64Layout_Invalid;
		if (!Dot) {
			// The matrix dimensions are machine dependendent.
			// Currently we do not support differentiation of machines.
			// So we just indicate the use of the complete matrix.
			vas = sme_reg_to_vas(MCInst_getOpVal(MI, OpNum));
		} else
			vas = get_vl_by_suffix(Dot[1]);
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_TILE, vas);
		break;
	}
	case AArch64_OP_GROUP_MatrixTileList: {
		unsigned MaxRegs = 8;
		unsigned RegMask = MCInst_getOpVal(MI, (OpNum));

		for (unsigned I = 0; I < MaxRegs; ++I) {
			unsigned Reg = RegMask & (1 << I);
			if (Reg == 0)
				continue;
			AArch64_get_detail_op(MI, 0)->is_list_member = true;
			AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_TILE_LIST, AArch64Layout_VL_D, AArch64_REG_ZAD0 + I);
		}
		break;
	}
	case AArch64_OP_GROUP_MRSSystemRegister:
	case AArch64_OP_GROUP_MSRSystemRegister: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		const AArch64SysReg_SysReg *Reg = AArch64SysReg_lookupSysRegByEncoding(Val);
		bool Read = (op_group == AArch64_OP_GROUP_MRSSystemRegister)
								   ? true
								   : false;

		bool isValidSysReg = (Reg && (Read ? Reg->Readable : Reg->Writeable) &&
			AArch64_testFeatureList(MI->csh->mode, Reg->FeaturesRequired));

		if (Reg && !isValidSysReg)
			Reg = AArch64SysReg_lookupSysRegByName(Reg->AltName);
		aarch64_sysop sysop;
		// If Reg is NULL it is a generic system register.
        if (Reg)
          sysop.reg = Reg->SysReg;
        else {
          sysop.reg.raw_val = Val;
        }
		aarch64_op_type type = (op_group == AArch64_OP_GROUP_MRSSystemRegister)
								   ? AArch64_OP_REG_MRS
								   : AArch64_OP_REG_MSR;
		sysop.sub_type = type;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSREG);
		break;
	}
	case AArch64_OP_GROUP_PSBHintOp: {
		unsigned psbhintop = MCInst_getOpVal(MI, OpNum);
		const AArch64PSBHint_PSB *PSB = AArch64PSBHint_lookupPSBByEncoding(psbhintop);
		aarch64_sysop sysop;
        if (PSB)
            sysop.alias = PSB->SysAlias;
        else
            sysop.alias.raw_val = psbhintop;
		sysop.sub_type = AArch64_OP_PSB;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_RPRFMOperand: {
		unsigned prfop = MCInst_getOpVal(MI, OpNum);
		const AArch64PRFM_PRFM *PRFM = AArch64PRFM_lookupPRFMByEncoding(prfop);
		aarch64_sysop sysop;
        if (PRFM)
            sysop.alias = PRFM->SysAlias;
        else
            sysop.alias.raw_val = prfop;
		sysop.sub_type = AArch64_OP_PRFM;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_ShiftedRegister: {
		AArch64_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		// Shift part is handled in printShifter()
		break;
	}
	case AArch64_OP_GROUP_Shifter: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		AArch64_AM_ShiftExtendType ShExtType = AArch64_AM_getShiftType(Val);
		AArch64_get_detail_op(MI, -1)->ext = llvm_to_cs_ext(ShExtType);
		AArch64_get_detail_op(MI, -1)->shift.type = llvm_to_cs_shift(ShExtType);
		AArch64_get_detail_op(MI, -1)->shift.value = AArch64_AM_getShiftValue(Val);
		break;
	}
	case AArch64_OP_GROUP_SIMDType10Operand: {
		unsigned RawVal = MCInst_getOpVal(MI, OpNum);
		uint64_t Val = AArch64_AM_decodeAdvSIMDModImmType10(RawVal);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		break;
	}
	case AArch64_OP_GROUP_SVCROp: {
		unsigned svcrop = MCInst_getOpVal(MI, OpNum);
		const AArch64SVCR_SVCR *SVCR = AArch64SVCR_lookupSVCRByEncoding(svcrop);
		aarch64_sysop sysop;
        if (SVCR)
            sysop.alias = SVCR->SysAlias;
        else
            sysop.alias.raw_val = svcrop;
		sysop.sub_type = AArch64_OP_SVCR;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_SVEPattern: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		const AArch64SVEPredPattern_SVEPREDPAT *Pat = AArch64SVEPredPattern_lookupSVEPREDPATByEncoding(Val);
		if (!Pat)
			break;
		aarch64_sysop sysop;
		sysop.alias = Pat->SysAlias;
		sysop.sub_type = AArch64_OP_SVEPREDPAT;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_SVEVecLenSpecifier: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);
		// Pattern has only 1 bit
		if (Val > 1)
			assert(0 && "Invalid vector length specifier");
		const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *Pat =
			AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByEncoding(Val);
		if (!Pat)
			break;
		aarch64_sysop sysop;
		sysop.alias = Pat->SysAlias;
		sysop.sub_type = AArch64_OP_SVEVECLENSPECIFIER;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		break;
	}
	case AArch64_OP_GROUP_SysCROperand: {
		uint64_t cimm = MCInst_getOpVal(MI, OpNum);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_CIMM, cimm);
		break;
	}
	case AArch64_OP_GROUP_SyspXzrPair: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		AArch64_set_detail_op_reg(MI, OpNum, Reg);
		AArch64_set_detail_op_reg(MI, OpNum, Reg);
		break;
	}
	case AArch64_OP_GROUP_SystemPStateField: {
		unsigned Val = MCInst_getOpVal(MI, OpNum);

		aarch64_sysop sysop;
		const AArch64PState_PStateImm0_15 *PStateImm15 = AArch64PState_lookupPStateImm0_15ByEncoding(Val);
		const AArch64PState_PStateImm0_1 *PStateImm1 = AArch64PState_lookupPStateImm0_1ByEncoding(Val);
		if (PStateImm15 && AArch64_testFeatureList(MI->csh->mode, PStateImm15->FeaturesRequired)) {
			sysop.alias = PStateImm15->SysAlias;
		sysop.sub_type = AArch64_OP_PSTATEIMM0_15;
			AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		}
		else if (PStateImm1 && AArch64_testFeatureList(MI->csh->mode, PStateImm1->FeaturesRequired)) {
			sysop.alias = PStateImm1->SysAlias;
		sysop.sub_type = AArch64_OP_PSTATEIMM0_1;
			AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
		}
		else {
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		}
		break;
	}
	case AArch64_OP_GROUP_VRegOperand: {
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		AArch64_set_detail_op_reg(MI, OpNum, Reg);
		break;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which original printer function is a template
/// with one argument.
static void add_cs_detail_template_1(MCInst *MI, aarch64_op_group op_group,
									 unsigned OpNum, uint64_t temp_arg_0)
{
	if (!detail_is_set(MI))
		return;
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case AArch64_OP_GROUP_GPRSeqPairsClassOperand_32:
	case AArch64_OP_GROUP_GPRSeqPairsClassOperand_64: {
		unsigned size = temp_arg_0;
		unsigned Reg = MCInst_getOpVal(MI, (OpNum));

		unsigned Sube = (size == 32) ? AArch64_sube32 : AArch64_sube64;
		unsigned Subo = (size == 32) ? AArch64_subo32 : AArch64_subo64;

		unsigned Even = MCRegisterInfo_getSubReg(MI->MRI, Reg, Sube);
		unsigned Odd = MCRegisterInfo_getSubReg(MI->MRI, Reg, Subo);
		AArch64_set_detail_op_reg(MI, OpNum, Even);
		AArch64_set_detail_op_reg(MI, OpNum, Odd);
		break;
	}
	case AArch64_OP_GROUP_Imm8OptLsl_int16_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int32_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int64_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int8_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint16_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint32_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint64_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint8_t: {
		unsigned UnscaledVal = MCInst_getOpVal(MI, (OpNum));
		unsigned Shift = MCInst_getOpVal(MI, (OpNum + 1));

		if ((UnscaledVal == 0) && (AArch64_AM_getShiftValue(Shift) != 0)) {
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, UnscaledVal);
			// Shift is handled in printShifter()
			break;
		}
		switch (op_group) {
		default:
			assert(0 && "Operand group for Imm8OptLsl not handled.");
		case AArch64_OP_GROUP_Imm8OptLsl_int16_t:
		case AArch64_OP_GROUP_Imm8OptLsl_int32_t:
		case AArch64_OP_GROUP_Imm8OptLsl_int64_t:
		case AArch64_OP_GROUP_Imm8OptLsl_int8_t: {
			int8_t Val =
				(int8_t)UnscaledVal * (1 << AArch64_AM_getShiftValue(Shift));
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		}
		case AArch64_OP_GROUP_Imm8OptLsl_uint16_t:
		case AArch64_OP_GROUP_Imm8OptLsl_uint32_t:
		case AArch64_OP_GROUP_Imm8OptLsl_uint64_t:
		case AArch64_OP_GROUP_Imm8OptLsl_uint8_t: {
			uint8_t Val =
					(uint8_t)UnscaledVal * (1 << AArch64_AM_getShiftValue(Shift));
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		}
		}
		break;
	}
	case AArch64_OP_GROUP_ImmScale_16:
	case AArch64_OP_GROUP_ImmScale_2:
	case AArch64_OP_GROUP_ImmScale_3:
	case AArch64_OP_GROUP_ImmScale_32:
	case AArch64_OP_GROUP_ImmScale_4:
	case AArch64_OP_GROUP_ImmScale_8: {
		unsigned Scale = temp_arg_0;
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM,
					Scale * MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_LogicalImm_int16_t:
	case AArch64_OP_GROUP_LogicalImm_int32_t:
	case AArch64_OP_GROUP_LogicalImm_int64_t:
	case AArch64_OP_GROUP_LogicalImm_int8_t: {
		unsigned TypeSize = temp_arg_0;
		uint64_t Val = AArch64_AM_decodeLogicalImmediate(MCInst_getOpVal(MI, OpNum), 8 * TypeSize);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Val);
		break;
	}
	case AArch64_OP_GROUP_Matrix_0:
	case AArch64_OP_GROUP_Matrix_16:
	case AArch64_OP_GROUP_Matrix_32:
	case AArch64_OP_GROUP_Matrix_64: {
		unsigned EltSize = temp_arg_0;
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_TILE, (AArch64Layout_VectorLayout) EltSize);
		break;
	}
	case AArch64_OP_GROUP_MatrixTileVector_0:
	case AArch64_OP_GROUP_MatrixTileVector_1: {
		bool isVertical = temp_arg_0;
		const char *RegName = AArch64_LLVM_getRegisterName(MCInst_getOpVal(MI, OpNum), AArch64_NoRegAltName);
		const char *Dot = strstr(RegName, ".");
		AArch64Layout_VectorLayout vas = AArch64Layout_Invalid;
		if (!Dot) {
			// The matrix dimensions are machine dependendent.
			// Currently we do not support differentiation of machines.
			// So we just indicate the use of the complete matrix.
			vas = sme_reg_to_vas(MCInst_getOpVal(MI, OpNum));
		} else
			vas = get_vl_by_suffix(Dot[1]);
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_TILE, vas);
		AArch64_get_detail_op(MI, -1)->sme.is_vertical = isVertical;
		break;
	}
	case AArch64_OP_GROUP_PostIncOperand_1:
	case AArch64_OP_GROUP_PostIncOperand_12:
	case AArch64_OP_GROUP_PostIncOperand_16:
	case AArch64_OP_GROUP_PostIncOperand_2:
	case AArch64_OP_GROUP_PostIncOperand_24:
	case AArch64_OP_GROUP_PostIncOperand_3:
	case AArch64_OP_GROUP_PostIncOperand_32:
	case AArch64_OP_GROUP_PostIncOperand_4:
	case AArch64_OP_GROUP_PostIncOperand_48:
	case AArch64_OP_GROUP_PostIncOperand_6:
	case AArch64_OP_GROUP_PostIncOperand_64:
	case AArch64_OP_GROUP_PostIncOperand_8: {
		uint64_t Imm = temp_arg_0;
		unsigned Reg = MCInst_getOpVal(MI, OpNum);
		if (Reg == AArch64_XZR) {
			AArch64_get_detail_op(MI, -1)->mem.disp = Imm;
			AArch64_get_detail(MI)->post_index = true;
			AArch64_inc_op_count(MI);
		} else
			AArch64_set_detail_op_reg(MI, OpNum, Reg);
		break;
	}
	case AArch64_OP_GROUP_PredicateAsCounter_0:
	case AArch64_OP_GROUP_PredicateAsCounter_16:
	case AArch64_OP_GROUP_PredicateAsCounter_32:
	case AArch64_OP_GROUP_PredicateAsCounter_64:
	case AArch64_OP_GROUP_PredicateAsCounter_8: {
		unsigned EltSize = temp_arg_0;
		AArch64_get_detail_op(MI, 0)->vas = EltSize;
		AArch64_set_detail_op_reg(MI, OpNum,
				MCInst_getOpVal(MI, OpNum) - AArch64_P0);
		break;
	}
	case AArch64_OP_GROUP_PrefetchOp_0:
	case AArch64_OP_GROUP_PrefetchOp_1: {
		bool IsSVEPrefetch = (bool) temp_arg_0;
		unsigned prfop = MCInst_getOpVal(MI, (OpNum));
		aarch64_sysop sysop;
		if (IsSVEPrefetch) {
			const AArch64SVEPRFM_SVEPRFM *PRFM = AArch64SVEPRFM_lookupSVEPRFMByEncoding(prfop);
			if (PRFM) {
				sysop.alias = PRFM->SysAlias;
				sysop.sub_type = AArch64_OP_SVEPRFM;
				AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
				break;
			}
		} else {
			const AArch64PRFM_PRFM *PRFM = AArch64PRFM_lookupPRFMByEncoding(prfop);
			if (PRFM && AArch64_testFeatureList(MI->csh->mode, PRFM->FeaturesRequired)) {
				sysop.alias = PRFM->SysAlias;
				sysop.sub_type = AArch64_OP_PRFM;
				AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSALIAS);
				break;
			}
		}
		AArch64_get_detail_op(MI, 0)->type = AArch64_OP_IMM;
		AArch64_get_detail_op(MI, 0)->imm = prfop;
		AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		AArch64_inc_op_count(MI);
		break;
	}
	case AArch64_OP_GROUP_SImm_16:
	case AArch64_OP_GROUP_SImm_8: {
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM,
				MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_SVELogicalImm_int16_t:
	case AArch64_OP_GROUP_SVELogicalImm_int32_t:
	case AArch64_OP_GROUP_SVELogicalImm_int64_t: {
		// General issue here that we do not save the operand type
		// for each operand. So we choose the largest type.
		uint64_t Val = MCInst_getOpVal(MI, OpNum);
		uint64_t DecodedVal = AArch64_AM_decodeLogicalImmediate(Val, 64);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, DecodedVal);
		break;
	}
	case AArch64_OP_GROUP_SVERegOp_0:
	case AArch64_OP_GROUP_SVERegOp_b:
	case AArch64_OP_GROUP_SVERegOp_d:
	case AArch64_OP_GROUP_SVERegOp_h:
	case AArch64_OP_GROUP_SVERegOp_q:
	case AArch64_OP_GROUP_SVERegOp_s: {
		char Suffix = (char) temp_arg_0;
		AArch64_get_detail_op(MI, 0)->vas = get_vl_by_suffix(Suffix);
		AArch64_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_UImm12Offset_1:
	case AArch64_OP_GROUP_UImm12Offset_16:
	case AArch64_OP_GROUP_UImm12Offset_2:
	case AArch64_OP_GROUP_UImm12Offset_4:
	case AArch64_OP_GROUP_UImm12Offset_8: {
		unsigned Scale = temp_arg_0;
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM,
				Scale * MCInst_getOpVal(MI, OpNum));
		break;
	}
	case AArch64_OP_GROUP_VectorIndex_1:
	case AArch64_OP_GROUP_VectorIndex_8: {
		assert(AArch64_get_detail(MI)->op_count > 0);
		unsigned Scale = temp_arg_0;
		unsigned VIndex = Scale * MCInst_getOpVal(MI, OpNum);
		// The index can ether be for one operand, or for each operand of a list.
		if (!AArch64_get_detail_op(MI, -1)->is_list_member) {
			AArch64_get_detail_op(MI, -1)->vector_index = VIndex;
			break;
		}
		for (int i = AArch64_get_detail(MI)->op_count - 1; i >= 0; --i) {
			if (!AArch64_get_detail(MI)->operands[i].is_list_member)
				break;
			AArch64_get_detail(MI)->operands[i].vector_index = VIndex;
		}
		break;
	}
	case AArch64_OP_GROUP_ZPRasFPR_128:
	case AArch64_OP_GROUP_ZPRasFPR_16:
	case AArch64_OP_GROUP_ZPRasFPR_32:
	case AArch64_OP_GROUP_ZPRasFPR_64:
	case AArch64_OP_GROUP_ZPRasFPR_8: {
		unsigned Base = AArch64_NoRegister;
		unsigned Width = temp_arg_0;
		switch (Width) {
		case 8:
			Base = AArch64_B0;
			break;
		case 16:
			Base = AArch64_H0;
			break;
		case 32:
			Base = AArch64_S0;
			break;
		case 64:
			Base = AArch64_D0;
			break;
		case 128:
			Base = AArch64_Q0;
			break;
		default:
			assert(0 && "Unsupported width");
		}
		unsigned Reg = MCInst_getOpVal(MI, (OpNum));
		AArch64_set_detail_op_reg(MI, OpNum, Reg - AArch64_Z0 + Base);
		break;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which original printer function is a template
/// with two arguments.
static void add_cs_detail_template_2(MCInst *MI, aarch64_op_group op_group,
									 unsigned OpNum, uint64_t temp_arg_0, uint64_t temp_arg_1)
{
	if (!detail_is_set(MI))
		return;
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case AArch64_OP_GROUP_ComplexRotationOp_180_90:
	case AArch64_OP_GROUP_ComplexRotationOp_90_0: {
		unsigned Angle = temp_arg_0;
		unsigned Remainder = temp_arg_1;
		unsigned Imm = (MCInst_getOpVal(MI, OpNum) * Angle) + Remainder;
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Imm);
		break;
	}
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_half_AArch64ExactFPImm_one:
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_half_AArch64ExactFPImm_two:
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_zero_AArch64ExactFPImm_one: {
		aarch64_exactfpimm ImmIs0 = temp_arg_0;
		aarch64_exactfpimm ImmIs1 = temp_arg_1;
		const AArch64ExactFPImm_ExactFPImm *Imm0Desc = AArch64ExactFPImm_lookupExactFPImmByEnum(ImmIs0);
		const AArch64ExactFPImm_ExactFPImm *Imm1Desc = AArch64ExactFPImm_lookupExactFPImmByEnum(ImmIs1);
		unsigned Val = MCInst_getOpVal(MI, (OpNum));
		aarch64_sysop sysop;
		sysop.imm = Val ? Imm1Desc->SysImm : Imm0Desc->SysImm;
		sysop.sub_type = AArch64_OP_EXACTFPIMM;
		AArch64_set_detail_op_sys(MI, OpNum, sysop, AArch64_OP_SYSIMM);
		break;
	}
	case AArch64_OP_GROUP_ImmRangeScale_2_1:
	case AArch64_OP_GROUP_ImmRangeScale_4_3: {
		uint64_t Scale = temp_arg_0;
		uint64_t Offset = temp_arg_1;
		unsigned FirstImm = Scale * MCInst_getOpVal(MI, (OpNum));
		AArch64_set_detail_op_imm_range(MI, OpNum, FirstImm, Offset);
		break;
	}
	case AArch64_OP_GROUP_MemExtend_w_128:
	case AArch64_OP_GROUP_MemExtend_w_16:
	case AArch64_OP_GROUP_MemExtend_w_32:
	case AArch64_OP_GROUP_MemExtend_w_64:
	case AArch64_OP_GROUP_MemExtend_w_8:
	case AArch64_OP_GROUP_MemExtend_x_128:
	case AArch64_OP_GROUP_MemExtend_x_16:
	case AArch64_OP_GROUP_MemExtend_x_32:
	case AArch64_OP_GROUP_MemExtend_x_64:
	case AArch64_OP_GROUP_MemExtend_x_8: {
		char SrcRegKind = (char) temp_arg_0;
		unsigned ExtWidth = temp_arg_1;
		bool SignExtend = MCInst_getOpVal(MI, OpNum);
		bool DoShift = MCInst_getOpVal(MI, OpNum + 1);
		AArch64_set_detail_shift_ext(MI, OpNum, SignExtend, DoShift, ExtWidth,
									 SrcRegKind);
		break;
	}
	case AArch64_OP_GROUP_TypedVectorList_0_b:
	case AArch64_OP_GROUP_TypedVectorList_0_d:
	case AArch64_OP_GROUP_TypedVectorList_0_h:
	case AArch64_OP_GROUP_TypedVectorList_0_q:
	case AArch64_OP_GROUP_TypedVectorList_0_s:
	case AArch64_OP_GROUP_TypedVectorList_16_b:
	case AArch64_OP_GROUP_TypedVectorList_1_d:
	case AArch64_OP_GROUP_TypedVectorList_2_d:
	case AArch64_OP_GROUP_TypedVectorList_2_s:
	case AArch64_OP_GROUP_TypedVectorList_4_h:
	case AArch64_OP_GROUP_TypedVectorList_4_s:
	case AArch64_OP_GROUP_TypedVectorList_8_b:
	case AArch64_OP_GROUP_TypedVectorList_8_h: {
		uint8_t NumLanes = (uint8_t) temp_arg_0;
		char LaneKind = (char) temp_arg_1;
		uint16_t Pair = ((NumLanes << 8) | LaneKind);

		AArch64Layout_VectorLayout vas = AArch64Layout_Invalid;
		switch (Pair) {
		default:
			printf("Typed vector list with NumLanes = %d and LaneKind = %c not handled.\n",
						NumLanes, LaneKind);
			assert(0);
		case ((8 << 8) | 'b'):
			vas = AArch64Layout_VL_8B;
			break;
		case ((4 << 8) | 'h'):
			vas = AArch64Layout_VL_4H;
			break;
		case ((2 << 8) | 's'):
			vas = AArch64Layout_VL_2S;
			break;
		case ((1 << 8) | 'd'):
			vas = AArch64Layout_VL_1D;
			break;
		case ((16 << 8) | 'b'):
			vas = AArch64Layout_VL_16B;
			break;
		case ((8 << 8) | 'h'):
			vas = AArch64Layout_VL_8H;
			break;
		case ((4 << 8) | 's'):
			vas = AArch64Layout_VL_4S;
			break;
		case ((2 << 8) | 'd'):
			vas = AArch64Layout_VL_2D;
			break;
		case 'b':
			vas = AArch64Layout_VL_B;
			break;
		case 'h':
			vas = AArch64Layout_VL_H;
			break;
		case 's':
			vas = AArch64Layout_VL_S;
			break;
		case 'd':
			vas = AArch64Layout_VL_D;
			break;
		case 'q':
			vas = AArch64Layout_VL_Q;
			break;
		case '\0':
			// Implicitly Typed register
			break;
		}

		unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
		unsigned NumRegs = get_vec_list_num_regs(MI, Reg);
		unsigned Stride = get_vec_list_stride(MI, Reg);
		Reg = get_vec_list_first_reg(MI, Reg);

		if ((MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPRRegClassID),
				 Reg) ||
			 MCRegisterClass_contains(
				 MCRegisterInfo_getRegClass(MI->MRI, AArch64_PPRRegClassID),
				 Reg)) &&
			NumRegs > 1 && Stride == 1 &&
			Reg < getNextVectorRegister(Reg, NumRegs - 1)) {
				AArch64_get_detail_op(MI, 0)->is_list_member = true;
				AArch64_get_detail_op(MI, 0)->vas = vas;
				AArch64_set_detail_op_reg(MI, OpNum, Reg);
				if (NumRegs > 1) {
					AArch64_get_detail_op(MI, 0)->is_list_member = true;
					AArch64_get_detail_op(MI, 0)->vas = vas;
					AArch64_set_detail_op_reg(MI, OpNum, getNextVectorRegister(Reg, NumRegs - 1));
				}
		} else {
			for (unsigned i = 0; i < NumRegs;
				 ++i, Reg = getNextVectorRegister(Reg, Stride)) {
				AArch64_get_detail_op(MI, 0)->is_list_member = true;
				AArch64_get_detail_op(MI, 0)->vas = vas;
				AArch64_set_detail_op_reg(MI, OpNum, Reg);
			}
		}
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// This function handles operands which original printer function is a template
/// with four arguments.
static void add_cs_detail_template_4(MCInst *MI, aarch64_op_group op_group,
									 unsigned OpNum, uint64_t temp_arg_0, uint64_t temp_arg_1,
									 uint64_t temp_arg_2, uint64_t temp_arg_3)
{
	if (!detail_is_set(MI))
		return;
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case AArch64_OP_GROUP_RegWithShiftExtend_0_128_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_16_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_16_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_32_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_32_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_64_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_64_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_8_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_8_w_s: {
		// signed (s) and unsigned (u) extend
		bool SignExtend = (bool) temp_arg_0;
		// Extend width
		int ExtWidth = (int) temp_arg_1;
		// w = word, x = doubleword
		char SrcRegKind = (char) temp_arg_2;
		// Vector register element/arrangement specifier:
		// B = 8bit, H = 16bit, S = 32bit, D = 64bit, Q = 128bit
		// No suffix = complete register
		// According to: ARM Reference manual supplement, doc number: DDI 0584
		char Suffix = (char) temp_arg_3;

		// Register will be added in printOperand() afterwards. Here we only handle
		// shift and extend.
		AArch64_get_detail_op(MI, -1)->vas = get_vl_by_suffix(Suffix);

		bool DoShift = ExtWidth != 8;
		if (!(SignExtend || DoShift || SrcRegKind == 'w'))
			return;

		AArch64_set_detail_shift_ext(MI, OpNum, SignExtend, DoShift, ExtWidth,
									 SrcRegKind);
		break;
	}
	}
}

void AArch64_add_cs_detail(MCInst *MI, int /* aarch64_op_group */ op_group,
					   va_list args) {
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	switch (op_group) {
	default:
		printf("Operand group %d not handled\n", op_group);
		break;
	case AArch64_OP_GROUP_AddSubImm:
	case AArch64_OP_GROUP_AdrLabel:
	case AArch64_OP_GROUP_AdrpLabel:
	case AArch64_OP_GROUP_AlignedLabel:
	case AArch64_OP_GROUP_AMNoIndex:
	case AArch64_OP_GROUP_ArithExtend:
	case AArch64_OP_GROUP_BarriernXSOption:
	case AArch64_OP_GROUP_BarrierOption:
	case AArch64_OP_GROUP_BTIHintOp:
	case AArch64_OP_GROUP_CondCode:
	case AArch64_OP_GROUP_ExtendedRegister:
	case AArch64_OP_GROUP_FPImmOperand:
	case AArch64_OP_GROUP_GPR64as32:
	case AArch64_OP_GROUP_GPR64x8:
	case AArch64_OP_GROUP_Imm:
	case AArch64_OP_GROUP_ImmHex:
	case AArch64_OP_GROUP_ImplicitlyTypedVectorList:
	case AArch64_OP_GROUP_InverseCondCode:
	case AArch64_OP_GROUP_MatrixIndex:
	case AArch64_OP_GROUP_MatrixTile:
	case AArch64_OP_GROUP_MatrixTileList:
	case AArch64_OP_GROUP_MRSSystemRegister:
	case AArch64_OP_GROUP_MSRSystemRegister:
	case AArch64_OP_GROUP_Operand:
	case AArch64_OP_GROUP_PSBHintOp:
	case AArch64_OP_GROUP_RPRFMOperand:
	case AArch64_OP_GROUP_ShiftedRegister:
	case AArch64_OP_GROUP_Shifter:
	case AArch64_OP_GROUP_SIMDType10Operand:
	case AArch64_OP_GROUP_SVCROp:
	case AArch64_OP_GROUP_SVEPattern:
	case AArch64_OP_GROUP_SVEVecLenSpecifier:
	case AArch64_OP_GROUP_SysCROperand:
	case AArch64_OP_GROUP_SyspXzrPair:
	case AArch64_OP_GROUP_SystemPStateField:
	case AArch64_OP_GROUP_VRegOperand: {
		unsigned op_num = va_arg(args, unsigned);
		add_cs_detail_general(MI, op_group, op_num);
		break;
	}
	case AArch64_OP_GROUP_GPRSeqPairsClassOperand_32:
	case AArch64_OP_GROUP_GPRSeqPairsClassOperand_64:
	case AArch64_OP_GROUP_Imm8OptLsl_int16_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int32_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int64_t:
	case AArch64_OP_GROUP_Imm8OptLsl_int8_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint16_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint32_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint64_t:
	case AArch64_OP_GROUP_Imm8OptLsl_uint8_t:
	case AArch64_OP_GROUP_ImmScale_16:
	case AArch64_OP_GROUP_ImmScale_2:
	case AArch64_OP_GROUP_ImmScale_3:
	case AArch64_OP_GROUP_ImmScale_32:
	case AArch64_OP_GROUP_ImmScale_4:
	case AArch64_OP_GROUP_ImmScale_8:
	case AArch64_OP_GROUP_LogicalImm_int16_t:
	case AArch64_OP_GROUP_LogicalImm_int32_t:
	case AArch64_OP_GROUP_LogicalImm_int64_t:
	case AArch64_OP_GROUP_LogicalImm_int8_t:
	case AArch64_OP_GROUP_Matrix_0:
	case AArch64_OP_GROUP_Matrix_16:
	case AArch64_OP_GROUP_Matrix_32:
	case AArch64_OP_GROUP_Matrix_64:
	case AArch64_OP_GROUP_MatrixTileVector_0:
	case AArch64_OP_GROUP_MatrixTileVector_1:
	case AArch64_OP_GROUP_PostIncOperand_1:
	case AArch64_OP_GROUP_PostIncOperand_12:
	case AArch64_OP_GROUP_PostIncOperand_16:
	case AArch64_OP_GROUP_PostIncOperand_2:
	case AArch64_OP_GROUP_PostIncOperand_24:
	case AArch64_OP_GROUP_PostIncOperand_3:
	case AArch64_OP_GROUP_PostIncOperand_32:
	case AArch64_OP_GROUP_PostIncOperand_4:
	case AArch64_OP_GROUP_PostIncOperand_48:
	case AArch64_OP_GROUP_PostIncOperand_6:
	case AArch64_OP_GROUP_PostIncOperand_64:
	case AArch64_OP_GROUP_PostIncOperand_8:
	case AArch64_OP_GROUP_PredicateAsCounter_0:
	case AArch64_OP_GROUP_PredicateAsCounter_16:
	case AArch64_OP_GROUP_PredicateAsCounter_32:
	case AArch64_OP_GROUP_PredicateAsCounter_64:
	case AArch64_OP_GROUP_PredicateAsCounter_8:
	case AArch64_OP_GROUP_PrefetchOp_0:
	case AArch64_OP_GROUP_PrefetchOp_1:
	case AArch64_OP_GROUP_SImm_16:
	case AArch64_OP_GROUP_SImm_8:
	case AArch64_OP_GROUP_SVELogicalImm_int16_t:
	case AArch64_OP_GROUP_SVELogicalImm_int32_t:
	case AArch64_OP_GROUP_SVELogicalImm_int64_t:
	case AArch64_OP_GROUP_SVERegOp_0:
	case AArch64_OP_GROUP_SVERegOp_b:
	case AArch64_OP_GROUP_SVERegOp_d:
	case AArch64_OP_GROUP_SVERegOp_h:
	case AArch64_OP_GROUP_SVERegOp_q:
	case AArch64_OP_GROUP_SVERegOp_s:
	case AArch64_OP_GROUP_UImm12Offset_1:
	case AArch64_OP_GROUP_UImm12Offset_16:
	case AArch64_OP_GROUP_UImm12Offset_2:
	case AArch64_OP_GROUP_UImm12Offset_4:
	case AArch64_OP_GROUP_UImm12Offset_8:
	case AArch64_OP_GROUP_VectorIndex_1:
	case AArch64_OP_GROUP_VectorIndex_8:
	case AArch64_OP_GROUP_ZPRasFPR_128:
	case AArch64_OP_GROUP_ZPRasFPR_16:
	case AArch64_OP_GROUP_ZPRasFPR_32:
	case AArch64_OP_GROUP_ZPRasFPR_64:
	case AArch64_OP_GROUP_ZPRasFPR_8: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t temp_arg_0 = va_arg(args, uint64_t);
		add_cs_detail_template_1(MI, op_group, op_num, temp_arg_0);
		break;
	}
	case AArch64_OP_GROUP_ComplexRotationOp_180_90:
	case AArch64_OP_GROUP_ComplexRotationOp_90_0:
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_half_AArch64ExactFPImm_one:
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_half_AArch64ExactFPImm_two:
	case AArch64_OP_GROUP_ExactFPImm_AArch64ExactFPImm_zero_AArch64ExactFPImm_one:
	case AArch64_OP_GROUP_ImmRangeScale_2_1:
	case AArch64_OP_GROUP_ImmRangeScale_4_3:
	case AArch64_OP_GROUP_MemExtend_w_128:
	case AArch64_OP_GROUP_MemExtend_w_16:
	case AArch64_OP_GROUP_MemExtend_w_32:
	case AArch64_OP_GROUP_MemExtend_w_64:
	case AArch64_OP_GROUP_MemExtend_w_8:
	case AArch64_OP_GROUP_MemExtend_x_128:
	case AArch64_OP_GROUP_MemExtend_x_16:
	case AArch64_OP_GROUP_MemExtend_x_32:
	case AArch64_OP_GROUP_MemExtend_x_64:
	case AArch64_OP_GROUP_MemExtend_x_8:
	case AArch64_OP_GROUP_TypedVectorList_0_b:
	case AArch64_OP_GROUP_TypedVectorList_0_d:
	case AArch64_OP_GROUP_TypedVectorList_0_h:
	case AArch64_OP_GROUP_TypedVectorList_0_q:
	case AArch64_OP_GROUP_TypedVectorList_0_s:
	case AArch64_OP_GROUP_TypedVectorList_16_b:
	case AArch64_OP_GROUP_TypedVectorList_1_d:
	case AArch64_OP_GROUP_TypedVectorList_2_d:
	case AArch64_OP_GROUP_TypedVectorList_2_s:
	case AArch64_OP_GROUP_TypedVectorList_4_h:
	case AArch64_OP_GROUP_TypedVectorList_4_s:
	case AArch64_OP_GROUP_TypedVectorList_8_b:
	case AArch64_OP_GROUP_TypedVectorList_8_h: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t temp_arg_0 = va_arg(args, uint64_t);
		uint64_t temp_arg_1 = va_arg(args, uint64_t);
		add_cs_detail_template_2(MI, op_group, op_num, temp_arg_0, temp_arg_1);
		break;
	}
	case AArch64_OP_GROUP_RegWithShiftExtend_0_128_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_16_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_32_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_64_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_0:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_0_8_x_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_16_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_16_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_32_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_32_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_64_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_64_w_s:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_8_w_d:
	case AArch64_OP_GROUP_RegWithShiftExtend_1_8_w_s: {
		unsigned op_num = va_arg(args, unsigned);
		uint64_t temp_arg_0 = va_arg(args, uint64_t);
		uint64_t temp_arg_1 = va_arg(args, uint64_t);
		uint64_t temp_arg_2 = va_arg(args, uint64_t);
		uint64_t temp_arg_3 = va_arg(args, uint64_t);
		add_cs_detail_template_4(MI, op_group, op_num, temp_arg_0, temp_arg_1,
								 temp_arg_2, temp_arg_3);
		break;
	}
	}
}

/// Adds a register AArch64 operand at position OpNum and increases the op_count by
/// one.
void AArch64_set_detail_op_reg(MCInst *MI, unsigned OpNum, aarch64_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	if (Reg == AArch64_REG_ZA || (Reg >= AArch64_REG_ZAB0 && Reg <= AArch64_REG_ZT0)) {
		// A tile register should be treated as SME operand.
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_TILE, sme_reg_to_vas(Reg));
		return;
	} else if (AArch64_get_detail(MI)->is_doing_sme && map_get_op_type(MI, OpNum) & CS_OP_MEM) {
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_SLICE_REG, AArch64Layout_Invalid);
		return;
	}
	if (map_get_op_type(MI, OpNum) & CS_OP_MEM) {
		AArch64_set_detail_op_mem(MI, OpNum, Reg);
		return;
	}

	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_REG);

	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_REG;
	AArch64_get_detail_op(MI, 0)->reg = Reg;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
	AArch64_get_detail(MI)->is_doing_sme = false; // Disable any sme operations.
}

/// Adds an immediate AArch64 operand at position OpNum and increases the op_count
/// by one.
void AArch64_set_detail_op_imm(MCInst *MI, unsigned OpNum, aarch64_op_type ImmType,
						   int64_t Imm)
{
	if (!detail_is_set(MI))
		return;

	if (AArch64_get_detail(MI)->is_doing_sme && map_get_op_type(MI, OpNum) & CS_OP_MEM) {
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_SLICE_OFF, AArch64Layout_Invalid);
		return;
	}
	AArch64_get_detail(MI)->is_doing_sme = false; // Disable any sme operations.
	if (map_get_op_type(MI, OpNum) & CS_OP_MEM) {
		AArch64_set_detail_op_mem(MI, OpNum, Imm);
		return;
	}


	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_IMM);
	assert(ImmType == AArch64_OP_IMM || ImmType == AArch64_OP_CIMM);

	AArch64_get_detail_op(MI, 0)->type = ImmType;
	AArch64_get_detail_op(MI, 0)->imm = Imm;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
}

void AArch64_set_detail_op_imm_range(MCInst *MI, unsigned OpNum,
						   int64_t FirstImm, int64_t Offset)
{
	if (!detail_is_set(MI))
		return;

	if (AArch64_get_detail(MI)->is_doing_sme && map_get_op_type(MI, OpNum) & CS_OP_MEM) {
		AArch64_set_detail_op_sme(MI, OpNum, AArch64_SME_MATRIX_SLICE_OFF_RANGE, AArch64Layout_Invalid, FirstImm, Offset);
		return;
	}

	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_IMM);

	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_IMM_RANGE;
	AArch64_get_detail_op(MI, 0)->imm_range.first = FirstImm;
	AArch64_get_detail_op(MI, 0)->imm_range.offset = Offset;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
}

/// Adds a memory AArch64 operand at position OpNum. op_count is *not* increased by
/// one. This is done by set_mem_access().
void AArch64_set_detail_op_mem(MCInst *MI, unsigned OpNum, uint64_t Val)
{
	if (!detail_is_set(MI))
		return;
	assert(map_get_op_type(MI, OpNum) & CS_OP_MEM);

	AArch64_set_mem_access(MI, true);

	cs_op_type secondary_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;
	switch (secondary_type) {
	default:
		assert(0 && "Secondary type not supported yet.");
	case CS_OP_REG: {
		assert(secondary_type == CS_OP_REG);
		bool is_index_reg = AArch64_get_detail_op(MI, 0)->mem.base != AArch64_REG_INVALID;
		if (is_index_reg)
			AArch64_get_detail_op(MI, 0)->mem.index = Val;
		else {
			AArch64_get_detail_op(MI, 0)->mem.base = Val;
		}

		if (MCInst_opIsTying(MI, OpNum)) {
			// Especially base registers can be writeback registers.
			// For this they tie an MC operand which has write
			// access. But this one is never processed in the printer
			// (because it is never emitted). Therefor it is never
			// added to the modified list.
			// Here we check for this case and add the memory register
			// to the modified list.
			map_add_implicit_write(MI, MCInst_getOpVal(MI, OpNum));
		}
		break;
	}
	case CS_OP_IMM: {
		assert(secondary_type == CS_OP_IMM);
		AArch64_get_detail_op(MI, 0)->mem.disp = Val;
		break;
	}
	}

	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_MEM;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_set_mem_access(MI, false);
	AArch64_get_detail(MI)->is_doing_sme = false; // Disable any sme operations.
}

/// Adds the shift and sign extend info to the previous operand.
/// op_count is *not* incremented by one.
void AArch64_set_detail_shift_ext(MCInst *MI, unsigned OpNum, bool SignExtend,
								  bool DoShift, unsigned ExtWidth, char SrcRegKind) {
	bool IsLSL = !SignExtend && SrcRegKind == 'x';
	if (IsLSL)
		AArch64_get_detail_op(MI, -1)->shift.type = AArch64_SFT_LSL;
	else {
		aarch64_extender ext = SignExtend ? AArch64_EXT_SXTB : AArch64_EXT_UXTB;
		switch (SrcRegKind) {
			default:
				assert(0 && "Extender not handled\n");
			case 'b':
				ext += 0;
				break;
			case 'h':
				ext += 1;
				break;
			case 'w':
				ext += 2;
				break;
			case 'x':
				ext += 3;
				break;
		}
		AArch64_get_detail_op(MI, -1)->ext = ext;
	}
	if (DoShift || IsLSL) {
		unsigned ShiftAmount = DoShift ? Log2_32(ExtWidth / 8) : 0;
		AArch64_get_detail_op(MI, -1)->shift.type = AArch64_SFT_LSL;
		AArch64_get_detail_op(MI, -1)->shift.value = ShiftAmount;
	}
}

/// Transforms the immediate of the operand to a float and stores it.
/// Increments the op_counter by one.
void AArch64_set_detail_op_float(MCInst *MI, unsigned OpNum, float Val)
{
	if (!detail_is_set(MI))
		return;
	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_FP;
	AArch64_get_detail_op(MI, 0)->fp = Val;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
	AArch64_get_detail(MI)->is_doing_sme = false; // Disable any sme operations.
}

/// Adds a the system operand and increases the op_count by
/// one.
void AArch64_set_detail_op_sys(MCInst *MI, unsigned OpNum,
	aarch64_sysop sys_op, aarch64_op_type type)
{
	if (!detail_is_set(MI))
		return;
	AArch64_get_detail_op(MI, 0)->type = type;
	AArch64_get_detail_op(MI, 0)->sysop = sys_op;
	AArch64_inc_op_count(MI);
	AArch64_get_detail(MI)->is_doing_sme = false; // Disable any sme operations.
}

/// Sets up a new SME operand at the currently active detail operand.
static void setup_sme_operand(MCInst *MI) {
	if (!detail_is_set(MI))
		return;

	memset(AArch64_get_detail_op(MI, 0), 0, sizeof(cs_aarch64));
	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_SME_MATRIX;
	AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.tile = AArch64_REG_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.slice_reg = AArch64_REG_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm = -1;
	AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm_range.first = -1;
	AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm_range.offset = -1;
}

/// Adds a SME matrix component to a SME operand.
void AArch64_set_detail_op_sme(MCInst *MI, unsigned OpNum, aarch64_sme_op_part part, AArch64Layout_VectorLayout vas, ...)
{
	/// Unfortunately SME operand components are not consistently set with unique printer functions.
	/// For example slice registers are set via normal printOperand.
	/// Here we check for any previously added SME operands at index -1 and -2 whenever this is called.
	/// And add it to it or create a new one and compine both of them.
	if (!detail_is_set(MI))
		return;

	va_list args;
	switch(part) {
	default:
		printf("Unhandled SME operand part %d\n", part);
		assert(0);
	case AArch64_SME_MATRIX_TILE_LIST:
		setup_sme_operand(MI);
		va_start(args, vas);
		int Tile = va_arg(args, int);
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE;
		AArch64_get_detail_op(MI, 0)->sme.tile = Tile;
		AArch64_get_detail_op(MI, 0)->vas = vas;
		break;
	case AArch64_SME_MATRIX_TILE:
		assert(map_get_op_type(MI, OpNum) == CS_OP_REG);
		setup_sme_operand(MI);
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE;
		AArch64_get_detail_op(MI, 0)->sme.tile = MCInst_getOpVal(MI, OpNum);
		AArch64_get_detail_op(MI, 0)->vas = vas;
		AArch64_get_detail(MI)->is_doing_sme = true;
		break;
	case AArch64_SME_MATRIX_SLICE_REG:
		assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);
		assert(AArch64_get_detail(MI)->op_count > 0);

		if (AArch64_get_detail_op(MI, -1)->type == AArch64_OP_SME_MATRIX) {
			// SME operand already present. Add the slice to it.
			AArch64_get_detail_op(MI, -1)->sme.type = AArch64_SME_OP_TILE_VEC;
			AArch64_get_detail_op(MI, -1)->sme.slice_reg = MCInst_getOpVal(MI, OpNum);
			return;
		}
		// No previous SME oeprand present. But the previous one should be the tile register.
		// Create a new one with that.
		AArch64_dec_op_count(MI);
		assert(AArch64_get_detail_op(MI, 0)->type == AArch64_OP_REG);
		assert(AArch64_get_detail_op(MI, 0)->access == map_get_op_access(MI, OpNum));

		aarch64_reg tile = AArch64_get_detail_op(MI, 0)->reg;
		setup_sme_operand(MI);
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE_VEC;
		AArch64_get_detail_op(MI, 0)->sme.tile = tile;
		AArch64_get_detail_op(MI, 0)->sme.slice_reg = MCInst_getOpVal(MI, OpNum);
		break;
	case AArch64_SME_MATRIX_SLICE_OFF:
		assert(AArch64_get_detail(MI)->op_count > 0);
		assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
		// Because we took care of the slice register before, the op at -1 must be a SME operand.
		assert(AArch64_get_detail_op(MI, -1)->type == AArch64_OP_SME_MATRIX);
		assert(AArch64_get_detail_op(MI, -1)->sme.slice_offset.imm == -1);

		AArch64_dec_op_count(MI);
		AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm = MCInst_getOpVal(MI, OpNum);
		AArch64_get_detail(MI)->is_doing_sme = false;
		break;
	case AArch64_SME_MATRIX_SLICE_OFF_RANGE:
		AArch64_dec_op_count(MI);
		va_start(args, vas);
		int8_t First = va_arg(args, int);
		int8_t Offset = va_arg(args, int);
		AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm_range.first = First;
		AArch64_get_detail_op(MI, 0)->sme.slice_offset.imm_range.offset = Offset;
		AArch64_get_detail_op(MI, 0)->sme.has_range_offset = true;
		AArch64_get_detail(MI)->is_doing_sme = false;
		va_end(args);
		break;
	}
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
}

static void insert_op(MCInst *MI, unsigned index, cs_aarch64_op op) {
	if (!detail_is_set(MI)) {
		return;
	}

	cs_aarch64_op *ops = AArch64_get_detail(MI)->operands;
	int i = AArch64_get_detail(MI)->op_count;
	assert(i < MAX_AARCH64_OPS);
	if (index == -1) {
		ops[i] = op;
		AArch64_inc_op_count(MI);
		return;
	}
	for (; i > 0 && i > index; --i) {
		ops[i] = ops[i - 1];
	}
	ops[index] = op;
	AArch64_inc_op_count(MI);
}

/// Inserts a float to the detail operands at @index.
/// If @index == -1, it pushes the operand to the end of the ops array.
/// Already present operands are moved.
void AArch64_insert_detail_op_float_at(MCInst *MI, unsigned index, double val,
				 cs_ac_type access)
{
	if (!detail_is_set(MI))
		return;

	assert(AArch64_get_detail(MI)->op_count < MAX_AARCH64_OPS);

	cs_aarch64_op op;
	AArch64_setup_op(&op);
	op.type = AArch64_OP_FP;
	op.fp = val;
	op.access = access;

	insert_op(MI, index, op);
}

/// Inserts a register to the detail operands at @index.
/// If @index == -1, it pushes the operand to the end of the ops array.
/// Already present operands are moved.
void AArch64_insert_detail_op_reg_at(MCInst *MI, unsigned index, aarch64_reg Reg,
				 cs_ac_type access)
{
	if (!detail_is_set(MI))
		return;

	assert(AArch64_get_detail(MI)->op_count < MAX_AARCH64_OPS);

	cs_aarch64_op op;
	AArch64_setup_op(&op);
	op.type = AArch64_OP_REG;
	op.reg = Reg;
	op.access = access;

	insert_op(MI, index, op);
}

/// Inserts a immediate to the detail operands at @index.
/// If @index == -1, it pushes the operand to the end of the ops array.
/// Already present operands are moved.
void AArch64_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;

	assert(AArch64_get_detail(MI)->op_count < MAX_AARCH64_OPS);

	cs_aarch64_op op;
	AArch64_setup_op(&op);
	op.type = AArch64_OP_IMM;
	op.imm = Imm;
	op.access = CS_AC_READ;

	insert_op(MI, index, op);
}

#endif
