/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#include "capstone/ppc.h"
#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_simple_types.h"
#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../utils.h"

#include "PPCLinkage.h"
#include "PPCMapping.h"
#include "PPCMCTargetDesc.h"

#define GET_REGINFO_MC_DESC
#include "PPCGenRegisterInfo.inc"

void PPC_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, PPCRegDesc, 289, 0, 0, PPCMCRegisterClasses, 103, 0, 0,
		PPCRegDiffLists, 0, PPCSubRegIdxLists, 57, PPCRegEncodingTable);
}

const char *PPC_reg_name(csh handle, unsigned int reg)
{
	return PPC_LLVM_getRegisterName(reg);
}

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// We do this after Instruction disassembly.
}

static const char * const insn_name_maps[] = {
    NULL, // PPC_INS_BCT
#include "PPCGenCSMappingInsnName.inc"
};

const char *PPC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
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
	{ PPC_GRP_JUMP,	"jump" },
	{ PPC_GRP_CALL, "call" },
	{ PPC_GRP_INT, "int" },
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
static void PPC_add_branch_predicates(MCInst *MI, const uint8_t *Bytes, size_t BytesLen) {
#ifndef CAPSTONE_DIET
	assert(MI && Bytes);
	if (BytesLen < 4)
		return;

	ppc_insn_form form = ppc_insns[MI->Opcode].suppl_info.ppc.form;
	bool b_form = ppc_is_b_form(form);
	if (!(b_form || form == PPC_INSN_FORM_XLFORM_2))
		return;

	uint32_t Inst = readBytes32(MI, Bytes);
	printf("0x%x\n", Inst);

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

	PPC_get_detail(MI)->bc.bi = bi % 4;
	PPC_get_detail(MI)->bc.crX = PPC_REG_CR0 + (bi / 4);
	PPC_get_detail(MI)->bc.bo = bo;
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
		assert(0 && "Invalid BH value.");
	case 0b00:
		PPC_get_detail(MI)->bc.bh = cond ? PPC_BH_NO_SUBROUTINE_RET : PPC_BH_SUBROUTINE_RET;
		break;
	case 0b01:
		PPC_get_detail(MI)->bc.bh = cond ? PPC_BH_RESERVED : PPC_BH_NO_SUBROUTINE_RET;
		break;
	case 0b10:
		PPC_get_detail(MI)->bc.bh = PPC_BH_RESERVED;
		break;
	case 0b11:
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
}

/// Inialize PPCs detail.
void PPC_init_cs_detail(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;
	memset(get_detail(MI), 0,
		   offsetof(cs_detail, arm) + sizeof(cs_arm));
	PPC_get_detail(MI)->bc.pred_cr = PPC_PRED_INVALID;
	PPC_get_detail(MI)->bc.pred_ctr = PPC_PRED_INVALID;
}

void PPC_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */info) {
	MI->MRI = (MCRegisterInfo*) info;
	PPC_LLVM_printInst(MI, MI->address, "", O);
}

bool PPC_getInstruction(csh handle, const uint8_t *bytes, size_t bytes_len,
						MCInst *instr, uint16_t *size, uint64_t address,
						void *info) {
	PPC_init_cs_detail(instr);
	DecodeStatus result = PPC_LLVM_getInstruction(handle, bytes, bytes_len, instr, size, address, info);
	PPC_set_instr_map_data(instr, bytes, bytes_len);
	return result != MCDisassembler_Fail;
}

bool PPC_getFeatureBits(unsigned int mode, unsigned int feature) {
  if ((feature == PPC_FeatureQPX) && (mode & CS_MODE_QPX) == 0) {
    return false;
  } else if ((feature == PPC_FeatureSPE) && (mode & CS_MODE_SPE) == 0) {
    return false;
  } else if ((feature == PPC_FeatureBookE) && (mode & CS_MODE_BOOKE) == 0) {
    return false;
  }
	// TODO: CS_MODE_PS

	// No AIX support for now.
	if (feature == PPC_FeatureModernAIXAs)
		return false;

	// By default support everything
	return true;
}

static const map_insn_ops insn_operands[] = {
#include "PPCGenCSMappingInsnOp.inc"
};

/// @brief Handles memory operands.
/// @param MI The MCInst.
/// @param OpNum The operand index.
static void handle_memory_operand(MCInst *MI, unsigned OpNum) {
	cs_op_type op_type = map_get_op_type(MI, OpNum);
	bool is_disp_offset = op_type == CS_OP_IMM ||
		(PPC_get_detail_op(MI, 0)->mem.base != PPC_REG_INVALID);
	PPC_set_detail_op_mem(MI, OpNum, MCInst_getOpVal(MI, OpNum), is_disp_offset);
}

static void add_cs_detail_general(MCInst *MI, ppc_op_group op_group,
								  unsigned OpNum) {
	if (!detail_is_set(MI))
		return;

	switch (op_group) {
	default:
		printf("General operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_Operand: {
		cs_op_type op_type = map_get_op_type(MI, OpNum);
		if (doing_mem(MI)) {
			// The memory operands use printOperand() to
			// emit their register and immediates.
			handle_memory_operand(MI, OpNum);
			return;
		}

		assert((op_type & CS_OP_MEM) == 0); // doing_mem should have been true.

		if (op_type == CS_OP_REG)
			PPC_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		else if (op_type == CS_OP_IMM)
			PPC_set_detail_op_imm(MI, OpNum, MCInst_getOpVal(MI, OpNum));
		else
			assert(0 && "Operand type not handled.");
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
		PPC_set_detail_op_imm(MI, OpNum, (uint32_t) MCInst_getOpVal(MI, OpNum));
		break;
	case PPC_OP_GROUP_U16ImmOperand:
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		PPC_set_detail_op_imm(MI, OpNum, (uint32_t) MCInst_getOpVal(MI, OpNum));
		break;
	case PPC_OP_GROUP_S5ImmOperand: {
		int Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		Imm = SignExtend32((Imm), 5);
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
		PPC_get_detail(MI)->bc.hint = (ppc_br_hint) MCInst_getOpVal(MI, OpNum);
		break;
	}
	case PPC_OP_GROUP_AbsBranchOperand: {
		if (!MCOperand_isImm(MCInst_getOperand(MI, OpNum)))
			// Handled in printOperand()
			return;
		unsigned Val = MCInst_getOpVal(MI, OpNum) << 2;
		int32_t Imm = SignExtend32(Val, 32);
		PPC_set_detail_op_imm(MI, OpNum, Imm);
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
		PPC_set_detail_op_imm(MI, OpNum, Address);
		break;
	}
	// Memory operands have their `set_mem_access()` calls
	// in PPCInstPrinter.
	case PPC_OP_GROUP_MemRegImm:
	case PPC_OP_GROUP_MemRegReg: {
		// These cases print 0 if the register is R0.
		// So no printOperand() function is called.
		// We must handle the zero case here.
		unsigned OpNumReg = 0;
		if (op_group == PPC_OP_GROUP_MemRegImm)
			OpNumReg = OpNum + 1;
		else
			OpNumReg = OpNum;

		MCOperand *Op = MCInst_getOperand(MI, OpNumReg);
		if (MCOperand_isReg(Op) && MCOperand_getReg(Op) == PPC_R0)
			PPC_set_detail_op_mem(MI, OpNum, PPC_R0, false);
		break;
	}
	case PPC_OP_GROUP_MemRegImmHash:
	case PPC_OP_GROUP_MemRegImm34:
	case PPC_OP_GROUP_MemRegImm34PCRel:
		// Handled in other printOperand functions.
		break;
	case PPC_OP_GROUP_LdStmModeOperand:
	case PPC_OP_GROUP_MandatoryInvertedPredicateOperand:
		printf("Operand group %d not implemented.\n", op_group);
		return;
	}
}

/// Fills cs_detail with the data of the operand.
/// Calls to this function should not be added by hand! Please checkout the
/// patch `AddCSDetail` of the CppTranslator.
void PPC_add_cs_detail(MCInst *MI, ppc_op_group op_group, va_list args)
{
	if (!detail_is_set(MI))
		return;

	switch (op_group) {
	default:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case PPC_OP_GROUP_RegImmShift: {
		// ARM_AM_ShiftOpc shift_opc = va_arg(args, ARM_AM_ShiftOpc);
		// unsigned shift_imm = va_arg(args, unsigned);
		// add_cs_detail_RegImmShift(MI, shift_opc, shift_imm);
		return;
	}
	case PPC_OP_GROUP_PredicateOperand: {
		unsigned OpNum = va_arg(args, unsigned);
		const char *Modifier = va_arg(args, const char *);
		if ((strcmp(Modifier, "cc") == 0) ||
				(strcmp(Modifier, "pm") == 0)) {
			unsigned Val = MCInst_getOpVal(MI, OpNum);
			unsigned bo = Val & 0x1f;
			unsigned bi = (Val & 0x1e0) >> 5;
			PPC_get_detail(MI)->bc.bo = bo;
			PPC_get_detail(MI)->bc.bi = bi % 4;
			PPC_get_detail(MI)->bc.crX = PPC_REG_CR0 + (bi / 4);
			PPC_get_detail(MI)->bc.pred_cr = PPC_get_branch_pred(bi, bo, true);
			PPC_get_detail(MI)->bc.pred_ctr = PPC_get_branch_pred(bi, bo, false);
			PPC_get_detail(MI)->bc.hint = PPC_get_hint(bo);
		}
		return;
	}
	case PPC_OP_GROUP_LdStmModeOperand:
	case PPC_OP_GROUP_MandatoryInvertedPredicateOperand:
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
		unsigned OpNum = va_arg(args, unsigned);
		add_cs_detail_general(MI, op_group, OpNum);
		return;
	}
	}
}

void PPC_set_detail_op_mem(MCInst *MI, unsigned OpNum, uint64_t Val, bool is_off_reg)
{
	if (!detail_is_set(MI))
		return;

	assert(map_get_op_type(MI, OpNum) & CS_OP_MEM);
	cs_op_type secondary_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;
	switch (secondary_type) {
	default:
		assert(0 && "Secondary type not supported yet.");
	case CS_OP_REG:
		if (is_off_reg)
			PPC_get_detail_op(MI, 0)->mem.offset = Val;
		else
			PPC_get_detail_op(MI, 0)->mem.base = Val;
		if (MCInst_opIsTying(MI, OpNum))
			map_add_implicit_write(MI, MCInst_getOpVal(MI, OpNum));
		break;
	case CS_OP_IMM:
		PPC_get_detail_op(MI, 0)->mem.disp = Val;
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
	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_REG);

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
	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_IMM);

	PPC_get_detail_op(MI, 0)->type = PPC_OP_IMM;
	PPC_get_detail_op(MI, 0)->imm = Imm;
	PPC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	PPC_inc_op_count(MI);
}

/// Returns the predicate wihtout branch hint information.
ppc_pred PPC_get_no_hint_pred(unsigned Code) {
		switch (Code) {
		default:
			assert(0 && "Invalid predicate code");
		case PPC_PRED_LT:
		case PPC_PRED_LT_MINUS:
		case PPC_PRED_LT_PLUS:
			return PPC_PRED_LT;
		case PPC_PRED_LE:
		case PPC_PRED_LE_MINUS:
		case PPC_PRED_LE_PLUS:
			return PPC_PRED_LE;
		case PPC_PRED_EQ:
		case PPC_PRED_EQ_MINUS:
		case PPC_PRED_EQ_PLUS:
			return PPC_PRED_EQ;
		case PPC_PRED_GE:
		case PPC_PRED_GE_MINUS:
		case PPC_PRED_GE_PLUS:
			return PPC_PRED_GE;
		case PPC_PRED_GT:
		case PPC_PRED_GT_MINUS:
		case PPC_PRED_GT_PLUS:
			return PPC_PRED_GT;
		case PPC_PRED_NE:
		case PPC_PRED_NE_MINUS:
		case PPC_PRED_NE_PLUS:
			return PPC_PRED_NE;
		case PPC_PRED_UN:
		case PPC_PRED_UN_MINUS:
		case PPC_PRED_UN_PLUS:
			return PPC_PRED_UN;
		case PPC_PRED_NU:
		case PPC_PRED_NU_MINUS:
		case PPC_PRED_NU_PLUS:
			return PPC_PRED_NU;
		case PPC_PRED_BIT_SET:
		case PPC_PRED_BIT_UNSET:
			assert(0 && "Invalid use of bit predicate code");
		}
}

void PPC_set_mem_access(MCInst *MI, bool status) {
	if (!detail_is_set(MI))
		return;
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

#endif
