/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#include "capstone/capstone.h"
#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h> // debug
#include <string.h>

#include "../../cs_simple_types.h"
#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../utils.h"

#include "PPCLinkage.h"
#include "PPCMapping.h"
#include "PPCMCTargetDesc.h"

static int P7InheritableFeatures[] = {
	PPC_DirectivePwr7,     PPC_FeatureAltivec,
	PPC_FeatureVSX,	       PPC_FeatureMFOCRF,
	PPC_FeatureFCPSGN,     PPC_FeatureFSqrt,
	PPC_FeatureFRE,	       PPC_FeatureFRES,
	PPC_FeatureFRSQRTE,    PPC_FeatureFRSQRTES,
	PPC_FeatureRecipPrec,  PPC_FeatureSTFIWX,
	PPC_FeatureLFIWAX,     PPC_FeatureFPRND,
	PPC_FeatureFPCVT,      PPC_FeatureISEL,
	PPC_FeaturePOPCNTD,    PPC_FeatureCMPB,
	PPC_FeatureLDBRX,      PPC_Feature64Bit,
	PPC_FeatureBPERMD,     PPC_FeatureExtDiv,
	PPC_FeatureMFTB,       PPC_DeprecatedDST,
	PPC_FeatureTwoConstNR, PPC_FeatureUnalignedFloats,
	PPC_FeatureISA2_06,    INT_MAX
};

static int *P7Features[] = { P7InheritableFeatures };

// Power8
static int P8AdditionalFeatures[] = { PPC_DirectivePwr8,
				      PPC_FeatureP8Altivec,
				      PPC_FeatureP8Vector,
				      PPC_FeatureP8Crypto,
				      PPC_FeatureHTM,
				      PPC_FeatureDirectMove,
				      PPC_FeatureICBT,
				      PPC_FeaturePartwordAtomic,
				      PPC_FeatureQuadwordAtomic,
				      PPC_FeaturePredictableSelectIsExpensive,
				      PPC_FeatureISA2_07,
				      PPC_FeatureCRBits,
				      INT_MAX };

static int P8SpecificFeatures[] = { PPC_FeatureAddiLoadFusion,
				    PPC_FeatureAddisLoadFusion, INT_MAX };

static int *P8Features[] = { P7InheritableFeatures, P8AdditionalFeatures,
			     P8SpecificFeatures };

static int P9AdditionalFeatures[] = { PPC_DirectivePwr9,
				      PPC_FeatureP9Altivec,
				      PPC_FeatureP9Vector,
				      PPC_FeaturePPCPreRASched,
				      PPC_FeaturePPCPostRASched,
				      PPC_FeatureISA3_0,
				      PPC_FeaturePredictableSelectIsExpensive,
				      INT_MAX };

static int P9SpecificFeatures[] = { PPC_FeatureVectorsUseTwoUnits, INT_MAX };

static int *P9Features[] = { P7InheritableFeatures, P8AdditionalFeatures,
			     P9AdditionalFeatures, P9SpecificFeatures };

static int P10AdditionalFeatures[] = { PPC_FeatureStoreFusion,
				       PPC_FeatureAddLogicalFusion,
				       PPC_FeatureLogicalAddFusion,
				       PPC_FeatureLogicalFusion,
				       PPC_FeatureArithAddFusion,
				       PPC_FeatureSha3Fusion,
				       PPC_DirectivePwr10,
				       PPC_FeatureISA3_1,
				       PPC_FeaturePrefixInstrs,
				       PPC_FeaturePCRelativeMemops,
				       PPC_FeatureP10Vector,
				       PPC_FeatureMMA,
				       PPC_FeaturePairedVectorMemops,
				       PPC_FeatureFastMFLR,
				       INT_MAX };

static int *P10Features[] = { P7InheritableFeatures, P8AdditionalFeatures,
			      P9AdditionalFeatures, P10AdditionalFeatures };

static int FutureAdditionalFeatures[] = { PPC_FeatureISAFuture, INT_MAX };

static int *FutureFeatures[] = { P7InheritableFeatures, P8AdditionalFeatures,
				 P9AdditionalFeatures, P10AdditionalFeatures,
				 FutureAdditionalFeatures };

static inline bool is_feature_of(int feature, int **feature_set, int set_size)
{
	for (size_t i = 0; i < set_size; ++i) {
		size_t j = 0;
		while (feature_set[i][j] != INT_MAX) {
			if (feature == feature_set[i][j]) {
				return true;
			}
			++j;
		}
	}
	return false;
}

#define GET_REGINFO_MC_DESC
#include "PPCGenRegisterInfo.inc"

void PPC_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, PPCRegDesc, PPC_REG_ENDING, 0, 0,
					  PPCMCRegisterClasses,
					  ARR_SIZE(PPCMCRegisterClasses), 0, 0,
					  PPCRegDiffLists, 0, PPCSubRegIdxLists,
					  ARR_SIZE(PPCSubRegIdxLists),
					  PPCRegEncodingTable);
}

const char *PPC_reg_name(csh handle, unsigned int reg)
{
	if (reg > PPC_REG_INVALID && reg < PPC_REG_ENDING)
		return PPC_LLVM_getRegisterName(reg);
	return NULL;
}

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// We do this after Instruction disassembly.
}

#ifndef CAPSTONE_DIET

static const char *const insn_name_maps[] = {
#include "PPCGenCSMappingInsnName.inc"
};

static const name_map insn_alias_mnem_map[] = {
#include "PPCGenCSAliasMnemMap.inc"
	{ PPC_INS_ALIAS_SLWI, "slwi" },
	{ PPC_INS_ALIAS_SRWI, "srwi" },
	{ PPC_INS_ALIAS_SLDI, "sldi" },
	{ PPC_INS_ALIAS_END, NULL },
};

#endif

const char *PPC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < PPC_INS_ALIAS_END && id > PPC_INS_ALIAS_BEGIN) {
		if (id - PPC_INS_ALIAS_BEGIN >= ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - PPC_INS_ALIAS_BEGIN - 1].name;
	}
	if (id >= PPC_INS_ENDING)
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ PPC_GRP_INVALID, NULL },
	{ PPC_GRP_JUMP, "jump" },
	{ PPC_GRP_CALL, "call" },
	{ PPC_GRP_RET, "ret" },
	{ PPC_GRP_INT, "int" },
	{ PPC_GRP_IRET, "iret" },
	{ PPC_GRP_PRIVILEGE, "privilege" },
	{ PPC_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture-specific groups
#include "PPCGenCSFeatureName.inc"
};
#endif

const char *PPC_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

const insn_map ppc_insns[] = {
#include "PPCGenCSMappingInsn.inc"
};

void PPC_check_updates_cr0(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI))
		return;
	cs_detail *detail = get_detail(MI);
	for (int i = 0; i < detail->regs_write_count; ++i) {
		if (detail->regs_write[i] == 0)
			return;
		if (detail->regs_write[i] == PPC_REG_CR0) {
			PPC_get_detail(MI)->update_cr0 = true;
			return;
		}
	}
#endif // CAPSTONE_DIET
}

/// Parses and adds the branch predicate information and the BH field.
static void PPC_add_branch_predicates(MCInst *MI, const uint8_t *Bytes,
				      size_t BytesLen)
{
	if (!detail_is_set(MI))
		return;
#ifndef CAPSTONE_DIET
	CS_ASSERT_RET(MI && Bytes);
	if (BytesLen < 4)
		return;

	ppc_insn_form form = ppc_insns[MI->Opcode].suppl_info.ppc.form;
	bool b_form = ppc_is_b_form(form);
	if (!(b_form || form == PPC_INSN_FORM_XLFORM_2))
		return;

	uint32_t Inst = readBytes32(MI, Bytes);

	uint8_t bi = 0;
	if (b_form)
		bi = (Inst & PPC_INSN_FORM_B_BI_MASK) >> 16;
	else
		bi = (Inst & PPC_INSN_FORM_XL_BI_MASK) >> 16;

	uint8_t bo = 0;
	if (b_form)
		bo = (Inst & PPC_INSN_FORM_B_BO_MASK) >> 21;
	else
		bo = (Inst & PPC_INSN_FORM_XL_BO_MASK) >> 21;

	PPC_get_detail(MI)->bc.bo = bo;
	PPC_get_detail(MI)->bc.bi = bi;
	PPC_get_detail(MI)->bc.crX_bit = bi % 4;
	PPC_get_detail(MI)->bc.crX = PPC_REG_CR0 + (bi / 4);
	PPC_get_detail(MI)->bc.hint = PPC_get_hint(bo);
	PPC_get_detail(MI)->bc.pred_cr = PPC_get_branch_pred(bi, bo, true);
	PPC_get_detail(MI)->bc.pred_ctr = PPC_get_branch_pred(bi, bo, false);

	if (ppc_is_b_form(form))
		return;

	uint8_t bh = (Inst & PPC_INSN_FORM_XL_BH_MASK) >> 11;
	uint16_t xo = (Inst & PPC_INSN_FORM_XL_XO_MASK) >> 1;
	// Pre-defined values for XO fields (PowerISA v3.1B)
	uint16_t bcctr_xo_field = 528;
	uint16_t bctar_xo_field = 560;
	bool cond = (xo == bcctr_xo_field || xo == bctar_xo_field);
	switch (bh) {
	default:
		CS_ASSERT_RET(0 && "Invalid BH value.");
	case 0:
		PPC_get_detail(MI)->bc.bh = cond ? PPC_BH_NO_SUBROUTINE_RET :
						   PPC_BH_SUBROUTINE_RET;
		break;
	case 1:
		PPC_get_detail(MI)->bc.bh = cond ? PPC_BH_RESERVED :
						   PPC_BH_NO_SUBROUTINE_RET;
		break;
	case 2:
		PPC_get_detail(MI)->bc.bh = PPC_BH_RESERVED;
		break;
	case 3:
		PPC_get_detail(MI)->bc.bh = PPC_BH_NOT_PREDICTABLE;
		break;
	}
#endif // CAPSTONE_DIET
}

void PPC_set_instr_map_data(MCInst *MI, const uint8_t *Bytes, size_t BytesLen)
{
	map_cs_id(MI, ppc_insns, ARR_SIZE(ppc_insns));
	map_implicit_reads(MI, ppc_insns);
	map_implicit_writes(MI, ppc_insns);
	map_groups(MI, ppc_insns);
	PPC_add_branch_predicates(MI, Bytes, BytesLen);
	PPC_check_updates_cr0(MI);
	const ppc_suppl_info *suppl_info = map_get_suppl_info(MI, ppc_insns);
	if (suppl_info) {
		PPC_get_detail(MI)->format = suppl_info->form;
	}
}

/// Initialize PPCs detail.
void PPC_init_cs_detail(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;
	memset(get_detail(MI), 0, offsetof(cs_detail, ppc) + sizeof(cs_ppc));
	PPC_get_detail(MI)->bc.bi = UINT8_MAX;
	PPC_get_detail(MI)->bc.bo = UINT8_MAX;
	PPC_get_detail(MI)->bc.crX = PPC_REG_INVALID;
	PPC_get_detail(MI)->bc.crX_bit = PPC_BI_INVALID;
	PPC_get_detail(MI)->bc.pred_cr = PPC_PRED_INVALID;
	PPC_get_detail(MI)->bc.pred_ctr = PPC_PRED_INVALID;
	PPC_get_detail(MI)->bc.hint = PPC_BR_NOT_GIVEN;
	PPC_get_detail(MI)->bc.bh = PPC_BH_INVALID;
}

void PPC_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info)
{
	MI->MRI = (MCRegisterInfo *)info;
	MI->fillDetailOps = detail_is_set(MI);
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	PPC_LLVM_printInst(MI, MI->address, "", O);
#ifndef CAPSTONE_DIET
	map_set_alias_id(MI, O, insn_alias_mnem_map,
			 ARR_SIZE(insn_alias_mnem_map));
#endif
}

bool PPC_getInstruction(csh handle, const uint8_t *bytes, size_t bytes_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info)
{
	PPC_init_cs_detail(instr);
	DecodeStatus result = PPC_LLVM_getInstruction(
		handle, bytes, bytes_len, instr, size, address, info);
	PPC_set_instr_map_data(instr, bytes, bytes_len);
	return result != MCDisassembler_Fail;
}

bool PPC_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == PPC_FeatureQPX) {
		return (mode & CS_MODE_QPX) != 0;
	} else if (feature == PPC_FeatureSPE) {
		return (mode & CS_MODE_SPE) != 0;
	} else if (feature == PPC_FeatureBookE) {
		return (mode & CS_MODE_BOOKE) != 0;
	} else if (feature == PPC_FeaturePS) {
		return (mode & CS_MODE_PS) != 0;
	} else if (feature == PPC_FeatureModernAIXAs) {
		return (mode & CS_MODE_MODERN_AIX_AS) != 0;
	} else if (feature == PPC_AIXOS) {
		return (mode & CS_MODE_AIX_OS) != 0 ||
		       (mode & CS_MODE_MODERN_AIX_AS) != 0;
	} else if (feature == PPC_FeatureMSYNC) {
		return (mode & CS_MODE_MSYNC) != 0;
	}
	if ((mode & (CS_MODE_PWR7 | CS_MODE_PWR8 | CS_MODE_PWR9 |
		     CS_MODE_PWR10 | CS_MODE_PPC_ISA_FUTURE)) == 0) {
		// By default support everything
		return true;
	}

	if (is_feature_of(feature, P7Features, ARR_SIZE(P7Features))) {
		return (mode & (CS_MODE_PWR7 | CS_MODE_PWR8 | CS_MODE_PWR9 |
				CS_MODE_PWR10 | CS_MODE_PPC_ISA_FUTURE));
	}
	if (is_feature_of(feature, P8Features, ARR_SIZE(P8Features))) {
		return (mode & (CS_MODE_PWR8 | CS_MODE_PWR9 | CS_MODE_PWR10 |
				CS_MODE_PPC_ISA_FUTURE));
	}
	if (is_feature_of(feature, P9Features, ARR_SIZE(P9Features))) {
		return (mode & (CS_MODE_PWR9 | CS_MODE_PWR10 |
				CS_MODE_PPC_ISA_FUTURE));
	}
	if (is_feature_of(feature, P10Features, ARR_SIZE(P10Features))) {
		return (mode & (CS_MODE_PWR10 | CS_MODE_PPC_ISA_FUTURE));
	}
	if (is_feature_of(feature, FutureFeatures, ARR_SIZE(FutureFeatures))) {
		return (mode & CS_MODE_PPC_ISA_FUTURE);
	}

	// By default support everything
	return true;
}

#ifndef CAPSTONE_DIET
static const map_insn_ops insn_operands[] = {
#include "PPCGenCSMappingInsnOp.inc"
};
#endif

/// @brief Handles memory operands.
/// @param MI The MCInst.
/// @param OpNum The operand index.
static void handle_memory_operand(MCInst *MI, unsigned OpNum)
{
	cs_op_type op_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;

	// If this is called from printOperand() we do not know if a
	// register is a base or an offset reg (imm is always disponent).
	// So we assume the base register is always added before the offset register
	// and set the flag appropriately.
	bool is_off_reg =
		((op_type == CS_OP_REG) &&
		 PPC_get_detail_op(MI, 0)->mem.base != PPC_REG_INVALID);
	PPC_set_detail_op_mem(MI, OpNum, MCInst_getOpVal(MI, OpNum),
			      is_off_reg);
}

static void add_cs_detail_general(MCInst *MI, ppc_op_group op_group,
				  unsigned OpNum)
{
	if (!detail_is_set(MI))
		return;

	switch (op_group) {
	default:
		printf("General operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_Operand: {
		cs_op_type op_type = map_get_op_type(MI, OpNum);

		// Check for memory operands emitted via printOperand()
		if (doing_mem(MI) && !(op_type & CS_OP_MEM)) {
			// Close previous memory operand
			set_mem_access(MI, false);
		} else if (doing_mem(MI) || (op_type & CS_OP_MEM)) {
			// The memory operands use printOperand() to
			// emit their register and immediates.
			if (!doing_mem(MI))
				set_mem_access(MI, true);
			handle_memory_operand(MI, OpNum);
			return;
		}

		CS_ASSERT_RET((op_type & CS_OP_MEM) ==
			      0); // doing_mem should have been true.

		if (op_type == CS_OP_REG)
			PPC_set_detail_op_reg(MI, OpNum,
					      MCInst_getOpVal(MI, OpNum));
		else if (op_type == CS_OP_IMM)
			PPC_set_detail_op_imm(MI, OpNum,
					      MCInst_getOpVal(MI, OpNum));
		else
			CS_ASSERT_RET(0 && "Operand type not handled.");
		break;
	}
	case PPC_OP_GROUP_ImmZeroOperand:
	case PPC_OP_GROUP_U1ImmOperand:
	case PPC_OP_GROUP_U2ImmOperand:
	case PPC_OP_GROUP_U3ImmOperand:
	case PPC_OP_GROUP_U4ImmOperand:
	case PPC_OP_GROUP_U5ImmOperand:
	case PPC_OP_GROUP_U6ImmOperand:
	case PPC_OP_GROUP_U7ImmOperand:
	case PPC_OP_GROUP_U8ImmOperand:
	case PPC_OP_GROUP_U10ImmOperand:
	case PPC_OP_GROUP_U12ImmOperand:
		PPC_set_detail_op_imm(MI, OpNum,
				      (uint32_t)MCInst_getOpVal(MI, OpNum));
		break;
	case PPC_OP_GROUP_U16ImmOperand:
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		PPC_set_detail_op_imm(MI, OpNum,
				      (uint32_t)MCInst_getOpVal(MI, OpNum));
		break;
	case PPC_OP_GROUP_S5ImmOperand: {
		int Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		Imm = SignExtend32((Imm), 5);
		PPC_set_detail_op_imm(MI, OpNum, Imm);
		break;
	}
	case PPC_OP_GROUP_S12ImmOperand: {
		int64_t Imm = SignExtend64(
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))), 12);
		if (doing_mem(MI)) {
			PPC_set_detail_op_mem(MI, OpNum, Imm, true);
			break;
		}
		PPC_set_detail_op_imm(MI, OpNum, Imm);
		break;
	}
	case PPC_OP_GROUP_S16ImmOperand: {
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		int16_t Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		if (doing_mem(MI)) {
			PPC_set_detail_op_mem(MI, OpNum, Imm, true);
			break;
		}
		PPC_set_detail_op_imm(MI, OpNum, Imm);
		break;
	}
	case PPC_OP_GROUP_S34ImmOperand: {
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		if (doing_mem(MI)) {
			PPC_set_detail_op_mem(MI, OpNum, Imm, true);
			break;
		}
		PPC_set_detail_op_imm(MI, OpNum, Imm);
		break;
	}
	case PPC_OP_GROUP_ATBitsAsHint: {
		PPC_get_detail(MI)->bc.hint =
			(ppc_br_hint)MCInst_getOpVal(MI, OpNum);
		break;
	}
	case PPC_OP_GROUP_AbsBranchOperand: {
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		unsigned Val = MCInst_getOpVal(MI, OpNum) << 2;
		PPC_check_safe_inc(MI);
		PPC_get_detail_op(MI, 0)->type = PPC_OP_IMM;
		PPC_get_detail_op(MI, 0)->imm = Val;
		PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		PPC_inc_op_count(MI);
		break;
	}
	case PPC_OP_GROUP_TLSCall:
		// Handled in PPCInstPrinter and printOperand.
		return;
	case PPC_OP_GROUP_crbitm: {
		unsigned CCReg = MCInst_getOpVal(MI, OpNum);
		PPC_set_detail_op_reg(MI, OpNum, CCReg);
		break;
	}
	case PPC_OP_GROUP_BranchOperand: {
		if (!MCOperand_isImm(MCInst_getOperand(MI, (OpNum))))
			// Handled in printOperand()
			return;
		int32_t Imm = SignExtend32(
			((unsigned)MCInst_getOpVal(MI, (OpNum)) << 2), 32);
		uint64_t Address = MI->address + Imm;
		if (IS_32BIT(MI->csh->mode))
			Address &= 0xffffffff;
		PPC_check_safe_inc(MI);
		PPC_get_detail_op(MI, 0)->type = PPC_OP_IMM;
		PPC_get_detail_op(MI, 0)->imm = Address;
		PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		PPC_inc_op_count(MI);
		break;
	}
	// Memory operands have their `set_mem_access()` calls
	// in PPCInstPrinter.
	case PPC_OP_GROUP_MemRegImm:
	case PPC_OP_GROUP_MemRegReg: {
		// These cases print 0 if the base register is R0.
		// So no printOperand() function is called.
		// We must handle the zero case here.
		unsigned OpNumReg = 0;
		if (op_group == PPC_OP_GROUP_MemRegImm)
			OpNumReg = OpNum + 1;
		else
			OpNumReg = OpNum;

		MCOperand *Op = MCInst_getOperand(MI, OpNumReg);
		if (MCOperand_isReg(Op) && MCOperand_getReg(Op) == PPC_R0) {
			PPC_get_detail_op(MI, 0)->mem.base = PPC_REG_ZERO;
			PPC_get_detail_op(MI, 0)->type = PPC_OP_MEM;
			PPC_get_detail_op(MI, 0)->access =
				map_get_op_access(MI, OpNum);
		}
		break;
	}
	case PPC_OP_GROUP_MemRegImmHash:
	case PPC_OP_GROUP_MemRegImm34:
	case PPC_OP_GROUP_MemRegImm34PCRel:
		// Handled in other printOperand functions.
		break;
	}
}

void PPC_add_cs_detail_1(MCInst *MI, ppc_op_group op_group, unsigned OpNum,
			 const char *Modifier)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	switch (op_group) {
	default:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_PredicateOperand: {
		if ((strcmp(Modifier, "cc") == 0) ||
		    (strcmp(Modifier, "pm") == 0)) {
			unsigned Val = MCInst_getOpVal(MI, OpNum);
			unsigned bo = Val & 0x1f;
			unsigned bi = (Val & 0x1e0) >> 5;
			PPC_get_detail(MI)->bc.bo = bo;
			PPC_get_detail(MI)->bc.bi = bi;
			PPC_get_detail(MI)->bc.crX_bit = bi % 4;
			PPC_get_detail(MI)->bc.crX = PPC_REG_CR0 + (bi / 4);
			PPC_get_detail(MI)->bc.pred_cr =
				PPC_get_branch_pred(bi, bo, true);
			PPC_get_detail(MI)->bc.pred_ctr =
				PPC_get_branch_pred(bi, bo, false);
			PPC_get_detail(MI)->bc.hint = PPC_get_hint(bo);
		}
		return;
	}
	}
}

/// Fills cs_detail with the data of the operand.
/// Calls to this function should not be added by hand! Please checkout the
/// patch `AddCSDetail` of the CppTranslator.
void PPC_add_cs_detail_0(MCInst *MI, ppc_op_group op_group, unsigned OpNo)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	switch (op_group) {
	default:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_S12ImmOperand:
	case PPC_OP_GROUP_Operand:
	case PPC_OP_GROUP_MemRegReg:
	case PPC_OP_GROUP_U6ImmOperand:
	case PPC_OP_GROUP_U5ImmOperand:
	case PPC_OP_GROUP_MemRegImm:
	case PPC_OP_GROUP_S16ImmOperand:
	case PPC_OP_GROUP_U2ImmOperand:
	case PPC_OP_GROUP_U16ImmOperand:
	case PPC_OP_GROUP_BranchOperand:
	case PPC_OP_GROUP_AbsBranchOperand:
	case PPC_OP_GROUP_U1ImmOperand:
	case PPC_OP_GROUP_TLSCall:
	case PPC_OP_GROUP_U3ImmOperand:
	case PPC_OP_GROUP_S5ImmOperand:
	case PPC_OP_GROUP_MemRegImmHash:
	case PPC_OP_GROUP_U4ImmOperand:
	case PPC_OP_GROUP_U10ImmOperand:
	case PPC_OP_GROUP_crbitm:
	case PPC_OP_GROUP_S34ImmOperand:
	case PPC_OP_GROUP_ImmZeroOperand:
	case PPC_OP_GROUP_MemRegImm34:
	case PPC_OP_GROUP_MemRegImm34PCRel:
	case PPC_OP_GROUP_U8ImmOperand:
	case PPC_OP_GROUP_U12ImmOperand:
	case PPC_OP_GROUP_U7ImmOperand:
	case PPC_OP_GROUP_ATBitsAsHint: {
		add_cs_detail_general(MI, op_group, OpNo);
		return;
	}
	}
}

void PPC_set_detail_op_mem(MCInst *MI, unsigned OpNum, uint64_t Val,
			   bool is_off_reg)
{
	if (!detail_is_set(MI))
		return;

	CS_ASSERT_RET(map_get_op_type(MI, OpNum) & CS_OP_MEM);
	cs_op_type secondary_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;

	switch (secondary_type) {
	default:
		CS_ASSERT_RET(0 && "Secondary type not supported yet.");
	case CS_OP_REG:
		if (is_off_reg) {
			PPC_get_detail_op(MI, 0)->mem.offset = Val;
			if (PPC_get_detail_op(MI, 0)->mem.base !=
			    PPC_REG_INVALID)
				set_mem_access(MI, false);
		} else {
			PPC_get_detail_op(MI, 0)->mem.base = Val;
			if (MCInst_opIsTying(MI, OpNum))
				map_add_implicit_write(
					MI, MCInst_getOpVal(MI, OpNum));
		}
		break;
	case CS_OP_IMM:
		PPC_get_detail_op(MI, 0)->mem.disp = Val;
		if (PPC_get_detail_op(MI, 0)->mem.base != PPC_REG_INVALID)
			set_mem_access(MI, false);
		break;
	}

	PPC_get_detail_op(MI, 0)->type = PPC_OP_MEM;
	PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
}

/// Adds a register PPC operand at position OpNum and increases the op_count by
/// one.
void PPC_set_detail_op_reg(MCInst *MI, unsigned OpNum, ppc_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	PPC_check_safe_inc(MI);
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_REG);

	PPC_get_detail_op(MI, 0)->type = PPC_OP_REG;
	PPC_get_detail_op(MI, 0)->reg = Reg;
	PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	PPC_inc_op_count(MI);
}

/// Adds an immediate PPC operand at position OpNum and increases the op_count
/// by one.
void PPC_set_detail_op_imm(MCInst *MI, unsigned OpNum, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	PPC_check_safe_inc(MI);
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_IMM);

	PPC_get_detail_op(MI, 0)->type = PPC_OP_IMM;
	PPC_get_detail_op(MI, 0)->imm = Imm;
	PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	PPC_inc_op_count(MI);
}

void PPC_set_mem_access(MCInst *MI, bool status)
{
	if (!detail_is_set(MI))
		return;
	PPC_check_safe_inc(MI);
	if ((!status && !doing_mem(MI)) || (status && doing_mem(MI)))
		return; // Nothing to do

	set_doing_mem(MI, status);
	if (status) {
		PPC_get_detail_op(MI, 0)->type = PPC_OP_MEM;
		PPC_get_detail_op(MI, 0)->mem.base = PPC_REG_INVALID;
		PPC_get_detail_op(MI, 0)->mem.offset = PPC_REG_INVALID;
		PPC_get_detail_op(MI, 0)->mem.disp = 0;

#ifndef CAPSTONE_DIET
		uint8_t access =
			map_get_op_access(MI, PPC_get_detail(MI)->op_count);
		PPC_get_detail_op(MI, 0)->access = access;
#endif
	} else {
		// done, select the next operand slot
		PPC_inc_op_count(MI);
	}
}

void PPC_setup_op(cs_ppc_op *op)
{
	memset(op, 0, sizeof(cs_ppc_op));
	op->type = PPC_OP_INVALID;
}

/// Inserts a immediate to the detail operands at @index.
/// Already present operands are moved.
void PPC_insert_detail_op_imm_at(MCInst *MI, unsigned index, int64_t Val,
				 cs_ac_type access)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	PPC_check_safe_inc(MI);

	cs_ppc_op op;
	PPC_setup_op(&op);
	op.type = PPC_OP_IMM;
	op.imm = Val;
	op.access = access;

	cs_ppc_op *ops = PPC_get_detail(MI)->operands;
	int i = PPC_get_detail(MI)->op_count - 1;
	for (; i >= index; --i) {
		ops[i + 1] = ops[i];
		if (i == index)
			break;
	}
	ops[index] = op;
	PPC_inc_op_count(MI);
}

#endif
