/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_AARCH64

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_simple_types.h"
#include "../../Mapping.h"
#include "../../MathExtras.h"
#include "../../utils.h"

#include "AArch64AddressingModes.h"
#include "AArch64BaseInfo.h"
#include "AArch64Linkage.h"
#include "AArch64Mapping.h"

void AArch64_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, AArch64RegDesc, 289, 0, 0, AArch64MCRegisterClasses, 103, 0, 0,
		AArch64RegDiffLists, 0, AArch64SubRegIdxLists, 57, 0);
}

const insn_map aarch64_insns[] = {
#include "AArch64GenCSMappingInsn.inc"
};

const char *AArch64_reg_name(csh handle, unsigned int reg)
{
	if (((cs_struct *)(uintptr_t)handle)->syntax & CS_OPT_SYNTAX_NOREGNAME) {
		return AArch64_LLVM_getRegisterName(reg, AArch64_NoRegAltName);
	}
	// TODO Add options for the other register names
	return AArch64_LLVM_getRegisterName(reg, AArch64_NoRegAltName);
}

void AArch64_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		memset(get_detail(MI), 0,
			   offsetof(cs_detail, aarch64) + sizeof(cs_aarch64));
	}
}


void AArch64_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, aarch64_insns, ARR_SIZE(aarch64_insns));
	map_implicit_reads(MI, aarch64_insns);
	map_implicit_writes(MI, aarch64_insns);
	// Check if updates flags
	map_groups(MI, aarch64_insns);
}

bool AArch64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
						MCInst *instr, uint16_t *size, uint64_t address,
						void *info) {
	AArch64_init_cs_detail(instr);
	bool Result = AArch64_LLVM_getInstruction(handle, code, code_len, instr, size, address,
								 info) != MCDisassembler_Fail;
	AArch64_set_instr_map_data(instr);
	return Result;
}

void AArch64_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info) {
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	AArch64_LLVM_printInstruction(MI, O, info);
}

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Done after disassembly
	return;
}

static const char *const insn_name_maps[] = {
	NULL, // AArch64_INS_INVALID
#include "AArch64GenCSMappingInsnName.inc"
};

const char *AArch64_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
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
			case ARM_OP_MEM:
				// registers appeared in memory references always being read
				if ((op->mem.base != AArch64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != AArch64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((aarch64->writeback) && (op->mem.base != AArch64_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
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

/// Initializes or closes a SME operand. If @init = true it sets up the operand.
/// If @init = false it closes it and increments op_count by one.
static void set_sme_operand(MCInst *MI, bool init) {
	if (!init) {
		assert(AArch64_get_detail_op(MI, 0)->sme.type != AArch64_SME_OP_INVALID &&
					 AArch64_get_detail_op(MI, 0)->sme.tile != AArch64_REG_INVALID);
		AArch64_get_detail(MI)->is_doing_sme = false;
		AArch64_inc_op_count(MI);
		return;
	}
	assert(AArch64_get_detail_op(MI, 0)->sme.type != AArch64_SME_OP_INVALID);

	AArch64_get_detail(MI)->is_doing_sme = true;
	AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.tile = AArch64_REG_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.slice_reg = AArch64_REG_INVALID;
	AArch64_get_detail_op(MI, 0)->sme.slice_offset = -1;
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
		Reg = MCRegisterInfo_getMatchingSuperReg(MI->MRI, RegL, AArch64_dsub,
									 FPR128RC);
	}
	return Reg;
}

static unsigned getNextVectorRegister(unsigned Reg, unsigned Stride /* = 1 */)
{
	while (Stride--) {
		if (Reg < AArch64_Q0 && Reg > AArch64_Q31 &&
				Reg < AArch64_Z0 && Reg > AArch64_Z31 &&
				Reg < AArch64_P0 && Reg > AArch64_P15)
			assert(0 && "Vector register expected!");
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

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function has no
/// specialities.
static void add_cs_detail_general(MCInst *MI, aarch64_op_group op_group,
								  unsigned OpNum) {
	if (!MI->csh->detail)
		return;

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case AArch64_OP_GROUP_Operand: {
		cs_op_type op_type = map_get_op_type(MI, OpNum);
		switch (op_type) {
		default:
			printf("Unhandled operand type 0x%x\n", op_type);
			assert(0);
		case AArch64_OP_REG:
			if (AArch64_get_detail(MI)->is_doing_sme) {
				AArch64_get_detail_op(MI, 0)->sme.slice_reg = MCInst_getOpVal(MI, OpNum);
				break;
			}
			AArch64_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
			break;
		case AArch64_OP_IMM:
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM,
						MCInst_getOpVal(MI, OpNum));
			break;
		}
		break;
	}
	case AArch64_OP_GROUP_AddSubImm:
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
		printf("Operand group %d not implemented\n", op_group);
		break;
	case AArch64_OP_GROUP_MatrixIndex: {
		assert(AArch64_get_detail(MI)->is_doing_sme);
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE_VEC;
		AArch64_get_detail_op(MI, 0)->sme.slice_offset = MCInst_getOpVal(MI, OpNum);
		set_sme_operand(MI, false);
		break;
	}
	case AArch64_OP_GROUP_MatrixTile: {
		set_sme_operand(MI, true);
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE;
		AArch64_get_detail_op(MI, 0)->sme.tile = MCInst_getOpVal(MI, OpNum);
		const char *RegName = AArch64_LLVM_getRegisterName(MCInst_getOpVal(MI, OpNum), AArch64_NoRegAltName);
		const char *Dot = strstr(RegName, ".");
		if (!Dot) {
			AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_Invalid;
			break;
		}
		switch (Dot[1]) {
			case 'b':
			case 'B':
				AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_B;
				break;
			case 'h':
			case 'H':
				AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_H;
				break;
			case 's':
			case 'S':
				AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_S;
				break;
			case 'd':
			case 'D':
				AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_D;
				break;
			case 'q':
			case 'Q':
				AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_Q;
				break;
		}
		break;
	}
	case AArch64_OP_GROUP_MatrixTileList: {
		unsigned MaxRegs = 8;
		unsigned RegMask = MCInst_getOpVal(MI, (OpNum));

		for (unsigned I = 0; I < MaxRegs; ++I) {
			unsigned Reg = RegMask & (1 << I);
			if (Reg == 0)
				continue;
			AArch64_set_detail_op_reg(MI, OpNum, AArch64_REG_ZAD0 + I);
		}
		AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_D;
	}
	case AArch64_OP_GROUP_MRSSystemRegister:
	case AArch64_OP_GROUP_MSRSystemRegister:
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
	case AArch64_OP_GROUP_VRegOperand:
		printf("Operand group %d not implemented\n", op_group);
		break;
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
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Scale * MCInst_getOpVal(MI, OpNum));
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
		set_sme_operand(MI, true);
		unsigned EltSize = temp_arg_0;
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE;
		AArch64_get_detail_op(MI, 0)->sme.tile = MCInst_getOpVal(MI, OpNum);
		AArch64_get_detail_op(MI, 0)->vas = (AArch64Layout_VectorLayout) EltSize;
		break;
	}
	case AArch64_OP_GROUP_MatrixTileVector_0:
	case AArch64_OP_GROUP_MatrixTileVector_1: {
		bool isVertical = temp_arg_0;
		AArch64_get_detail_op(MI, 0)->sme.type = AArch64_SME_OP_TILE_VEC;
		AArch64_get_detail_op(MI, 0)->sme.tile = MCInst_getOpVal(MI, OpNum);
		AArch64_get_detail_op(MI, 0)->sme.is_vertical = isVertical;
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
		aarch64_reg Reg = MCInst_getOpVal(MI, OpNum);
		if (Reg == AArch64_XZR)
			AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, Imm);
		else
			AArch64_set_detail_op_reg(MI, OpNum, Reg);
		break;
	}
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
	case AArch64_OP_GROUP_ZPRasFPR_8:
		printf("Operand group %d not implemented\n", op_group);
		break;
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
		unsigned Val = MCInst_getOpVal(MI, (OpNum));
		aarch64_exactfpimm fp;
		if (Val)
			fp = ImmIs1;
		else
			fp = ImmIs0;
		switch (fp) {
		default:
			assert(0 && "Unknown exact FP value.");
		case AArch64_EXACTFPIMM_HALF:
			AArch64_set_detail_op_float(MI, OpNum, 0.5);
			break;
		case AArch64_EXACTFPIMM_ONE:
			AArch64_set_detail_op_float(MI, OpNum, 1.0);
			break;
		case AArch64_EXACTFPIMM_TWO:
			AArch64_set_detail_op_float(MI, OpNum, 2.0);
			break;
		case AArch64_EXACTFPIMM_ZERO:
			AArch64_set_detail_op_float(MI, OpNum, 0.0);
			break;
		}
		break;
	}
	case AArch64_OP_GROUP_ImmRangeScale_2_1:
	case AArch64_OP_GROUP_ImmRangeScale_4_3: {
		uint64_t Scale = temp_arg_0;
		uint64_t Offset = temp_arg_1;
		unsigned FirstImm = Scale * MCInst_getOpVal(MI, (OpNum));
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, FirstImm);
		AArch64_set_detail_op_imm(MI, OpNum, AArch64_OP_IMM, FirstImm + Offset);
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
				AArch64_get_detail_op(MI, 0)->vas = vas;
				AArch64_set_detail_op_reg(MI, OpNum, Reg);
				if (NumRegs > 1) {
					AArch64_get_detail_op(MI, 0)->vas = vas;
					AArch64_set_detail_op_reg(MI, OpNum, getNextVectorRegister(Reg, NumRegs - 1));
				}
		} else {
			for (unsigned i = 0; i < NumRegs;
				 ++i, Reg = getNextVectorRegister(Reg, Stride)) {
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

		switch (Suffix) {
		default:
			printf("ERROR: Vector register suffix %c not handled.\n", Suffix);
			assert(0);
		case 'b':
			AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_B;
			break;
		case 'h':
			AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_H;
			break;
		case 's':
			AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_S;
			break;
		case 'd':
			AArch64_get_detail_op(MI, 0)->vas = AArch64Layout_VL_D;
			break;
		}

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
	switch (op_group) {
	default:
		printf("Operand group %d not handled\n", op_group);
		break;
	case AArch64_OP_GROUP_AddSubImm:
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
	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_REG);

	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_REG;
	AArch64_get_detail_op(MI, 0)->reg = Reg;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
}

/// Adds an immediate AArch64 operand at position OpNum and increases the op_count
/// by one.
void AArch64_set_detail_op_imm(MCInst *MI, unsigned OpNum, aarch64_op_type ImmType,
						   int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	assert(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	assert(map_get_op_type(MI, OpNum) == CS_OP_IMM);
	assert(ImmType == AArch64_OP_IMM || ImmType == AArch64_OP_CIMM);

	AArch64_get_detail_op(MI, 0)->type = ImmType;
	AArch64_get_detail_op(MI, 0)->imm = Imm;
	AArch64_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	AArch64_inc_op_count(MI);
}

/// Adds the operand to the previously added memory operand.
void AArch64_set_detail_op_mem_offset(MCInst *MI, unsigned OpNum, uint64_t Val)
{
	assert(map_get_op_type(MI, OpNum) & CS_OP_MEM);

	if (!doing_mem(MI)) {
		assert((AArch64_get_detail_op(MI, -1) != NULL) &&
			   (AArch64_get_detail_op(MI, -1)->type == AArch64_OP_MEM));
		AArch64_dec_op_count(MI);
	}

	if ((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM)
		AArch64_set_detail_op_mem(MI, OpNum, false, Val);
	else if ((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG)
		AArch64_set_detail_op_mem(MI, OpNum, true, Val);
	else
		assert(0 && "Memory type incorrect.");

	if (!doing_mem(MI))
		AArch64_inc_op_count(MI);
}

/// Adds a memory AArch64 operand at position OpNum. op_count is *not* increased by
/// one. This is done by set_mem_access().
void AArch64_set_detail_op_mem(MCInst *MI, unsigned OpNum, bool is_index_reg,
						   uint64_t Val)
{
	if (!detail_is_set(MI))
		return;
	assert(map_get_op_type(MI, OpNum) & CS_OP_MEM);
	cs_op_type secondary_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;
	switch (secondary_type) {
	default:
		assert(0 && "Secondary type not supported yet.");
	case CS_OP_REG: {
		assert(secondary_type == CS_OP_REG);
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
}

/// Adds the shift and sign extend info of the currently edited operand.
/// op_count is *not* incremented by one.
void AArch64_set_detail_shift_ext(MCInst *MI, unsigned OpNum, bool SignExtend,
								  bool DoShift, unsigned ExtWidth, char SrcRegKind) {
	bool IsLSL = !SignExtend && SrcRegKind == 'x';
	if (IsLSL)
		AArch64_get_detail_op(MI, 0)->shift.type = AArch64_SFT_LSL;
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
		AArch64_get_detail_op(MI, 0)->ext = ext;
	}
	if (DoShift || IsLSL)
		AArch64_get_detail_op(MI, 0)->shift.value = Log2_32(ExtWidth / 8);
}

/// Transforms the immediate of the operand to a float and stores it.
/// Increments the op_counter by one.
void AArch64_set_detail_op_float(MCInst *MI, unsigned OpNum, float Val)
{
	if (!detail_is_set(MI))
		return;
	AArch64_get_detail_op(MI, 0)->type = AArch64_OP_FP;
	AArch64_get_detail_op(MI, 0)->fp = Val;
	AArch64_inc_op_count(MI);
}

#endif
