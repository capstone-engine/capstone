/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_AARCH64

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_simple_types.h"
#include "../../Mapping.h"
#include "../../utils.h"

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

/// Fills cs_detail with the data of the operand.
/// This function handles operands which's original printer function has no
/// specialities.
static void add_cs_detail_general(MCInst *MI, aarch64_op_group op_group,
								  unsigned OpNum) {
	if (!MI->csh->detail)
		return;
	cs_op_type op_type = map_get_op_type(MI, OpNum);

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
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
	case AArch64_OP_GROUP_TypedVectorList_8_h:
		printf("Operand group %d not implemented\n", op_group);
		break;
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
		bool SignExtend ;
		int ExtWidth;
		char SrcRegKind;
		char Suffix;

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

#endif
