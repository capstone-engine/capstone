#ifndef CAPSTONE_ARC_H
#define CAPSTONE_ARC_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"
#include "cs_operand.h"

/// Operand type for instruction's operands
typedef enum arc_op_type {
	ARC_OP_INVALID = CS_OP_INVALID, ///< Invalid
	ARC_OP_REG = CS_OP_REG, ///< Register operand
	ARC_OP_IMM = CS_OP_IMM, ///< Immediate operand
} arc_op_type;

/// Instruction operand
typedef struct cs_arc_op {
	arc_op_type type; //< operand type
	union {
		unsigned int reg; /// register value for REG operand
		int64_t imm; /// immediate value for IMM operand
	};

	/// How is this operand accessed? (READ, WRITE or READ|WRITE)
	/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	enum cs_ac_type access;
} cs_arc_op;

#define NUM_ARC_OPS 8

/// Instruction structure
typedef struct cs_arc {
	/// Number of operands of this instruction,
	/// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_arc_op operands[NUM_ARC_OPS]; ///< operands for this instruction.
} cs_arc;

/// ARC registers
typedef enum arc_reg {
	// generated content <ARCGenCSRegEnum.inc> begin
	// clang-format off

	ARC_REG_INVALID = 0,
	ARC_REG_BLINK = 1,
	ARC_REG_FP = 2,
	ARC_REG_GP = 3,
	ARC_REG_ILINK = 4,
	ARC_REG_SP = 5,
	ARC_REG_R0 = 6,
	ARC_REG_R1 = 7,
	ARC_REG_R2 = 8,
	ARC_REG_R3 = 9,
	ARC_REG_R4 = 10,
	ARC_REG_R5 = 11,
	ARC_REG_R6 = 12,
	ARC_REG_R7 = 13,
	ARC_REG_R8 = 14,
	ARC_REG_R9 = 15,
	ARC_REG_R10 = 16,
	ARC_REG_R11 = 17,
	ARC_REG_R12 = 18,
	ARC_REG_R13 = 19,
	ARC_REG_R14 = 20,
	ARC_REG_R15 = 21,
	ARC_REG_R16 = 22,
	ARC_REG_R17 = 23,
	ARC_REG_R18 = 24,
	ARC_REG_R19 = 25,
	ARC_REG_R20 = 26,
	ARC_REG_R21 = 27,
	ARC_REG_R22 = 28,
	ARC_REG_R23 = 29,
	ARC_REG_R24 = 30,
	ARC_REG_R25 = 31,
	ARC_REG_R30 = 32,
	ARC_REG_R32 = 33,
	ARC_REG_R33 = 34,
	ARC_REG_R34 = 35,
	ARC_REG_R35 = 36,
	ARC_REG_R36 = 37,
	ARC_REG_R37 = 38,
	ARC_REG_R38 = 39,
	ARC_REG_R39 = 40,
	ARC_REG_R40 = 41,
	ARC_REG_R41 = 42,
	ARC_REG_R42 = 43,
	ARC_REG_R43 = 44,
	ARC_REG_R44 = 45,
	ARC_REG_R45 = 46,
	ARC_REG_R46 = 47,
	ARC_REG_R47 = 48,
	ARC_REG_R48 = 49,
	ARC_REG_R49 = 50,
	ARC_REG_R50 = 51,
	ARC_REG_R51 = 52,
	ARC_REG_R52 = 53,
	ARC_REG_R53 = 54,
	ARC_REG_R54 = 55,
	ARC_REG_R55 = 56,
	ARC_REG_R56 = 57,
	ARC_REG_R57 = 58,
	ARC_REG_R58 = 59,
	ARC_REG_R59 = 60,
	ARC_REG_R60 = 61,
	ARC_REG_R61 = 62,
	ARC_REG_R62 = 63,
	ARC_REG_R63 = 64,
	ARC_REG_STATUS32 = 65,
	ARC_REG_ENDING, // 66

	// clang-format on
	// generated content <ARCGenCSRegEnum.inc> end
} arc_reg;

/// ARC instruction
typedef enum arc_insn {
	// generated content <ARCGenCSInsnEnum.inc> begin
	// clang-format off

	ARC_INS_INVALID,
	ARC_INS_h,
	ARC_INS_PBR,
	ARC_INS_ERROR_FLS,
	ARC_INS_ERROR_FFS,
	ARC_INS_PLDFI,
	ARC_INS_STB_FAR,
	ARC_INS_STH_FAR,
	ARC_INS_ST_FAR,
	ARC_INS_ADC,
	ARC_INS_ADC_F,
	ARC_INS_ADD_S,
	ARC_INS_ADD,
	ARC_INS_ADD_F,
	ARC_INS_AND,
	ARC_INS_AND_F,
	ARC_INS_ASL_S,
	ARC_INS_ASL,
	ARC_INS_ASL_F,
	ARC_INS_ASR_S,
	ARC_INS_ASR,
	ARC_INS_ASR_F,
	ARC_INS_BCLR_S,
	ARC_INS_BEQ_S,
	ARC_INS_BGE_S,
	ARC_INS_BGT_S,
	ARC_INS_BHI_S,
	ARC_INS_BHS_S,
	ARC_INS_BL,
	ARC_INS_BLE_S,
	ARC_INS_BLO_S,
	ARC_INS_BLS_S,
	ARC_INS_BLT_S,
	ARC_INS_BL_S,
	ARC_INS_BMSK_S,
	ARC_INS_BNE_S,
	ARC_INS_B,
	ARC_INS_BREQ_S,
	ARC_INS_BRNE_S,
	ARC_INS_BR,
	ARC_INS_BSET_S,
	ARC_INS_BTST_S,
	ARC_INS_B_S,
	ARC_INS_CMP_S,
	ARC_INS_CMP,
	ARC_INS_LD_S,
	ARC_INS_MOV_S,
	ARC_INS_EI_S,
	ARC_INS_ENTER_S,
	ARC_INS_FFS_F,
	ARC_INS_FFS,
	ARC_INS_FLS_F,
	ARC_INS_FLS,
	ARC_INS_ABS_S,
	ARC_INS_ADD1_S,
	ARC_INS_ADD2_S,
	ARC_INS_ADD3_S,
	ARC_INS_AND_S,
	ARC_INS_BIC_S,
	ARC_INS_BRK_S,
	ARC_INS_EXTB_S,
	ARC_INS_EXTH_S,
	ARC_INS_JEQ_S,
	ARC_INS_JL_S,
	ARC_INS_JL_S_D,
	ARC_INS_JNE_S,
	ARC_INS_J_S,
	ARC_INS_J_S_D,
	ARC_INS_LSR_S,
	ARC_INS_MPYUW_S,
	ARC_INS_MPYW_S,
	ARC_INS_MPY_S,
	ARC_INS_NEG_S,
	ARC_INS_NOP_S,
	ARC_INS_NOT_S,
	ARC_INS_OR_S,
	ARC_INS_SEXB_S,
	ARC_INS_SEXH_S,
	ARC_INS_SUB_S,
	ARC_INS_SUB_S_NE,
	ARC_INS_SWI_S,
	ARC_INS_TRAP_S,
	ARC_INS_TST_S,
	ARC_INS_UNIMP_S,
	ARC_INS_XOR_S,
	ARC_INS_LDB_S,
	ARC_INS_LDH_S,
	ARC_INS_J,
	ARC_INS_JL,
	ARC_INS_JLI_S,
	ARC_INS_LDB_AB,
	ARC_INS_LDB_AW,
	ARC_INS_LDB_DI_AB,
	ARC_INS_LDB_DI_AW,
	ARC_INS_LDB_DI,
	ARC_INS_LDB_X_AB,
	ARC_INS_LDB_X_AW,
	ARC_INS_LDB_X_DI_AB,
	ARC_INS_LDB_X_DI_AW,
	ARC_INS_LDB_X_DI,
	ARC_INS_LDB_X,
	ARC_INS_LDB,
	ARC_INS_LDH_AB,
	ARC_INS_LDH_AW,
	ARC_INS_LDH_DI_AB,
	ARC_INS_LDH_DI_AW,
	ARC_INS_LDH_DI,
	ARC_INS_LDH_S_X,
	ARC_INS_LDH_X_AB,
	ARC_INS_LDH_X_AW,
	ARC_INS_LDH_X_DI_AB,
	ARC_INS_LDH_X_DI_AW,
	ARC_INS_LDH_X_DI,
	ARC_INS_LDH_X,
	ARC_INS_LDH,
	ARC_INS_LDI_S,
	ARC_INS_LD_AB,
	ARC_INS_LD_AW,
	ARC_INS_LD_DI_AB,
	ARC_INS_LD_DI_AW,
	ARC_INS_LD_DI,
	ARC_INS_LD_S_AS,
	ARC_INS_LD,
	ARC_INS_LEAVE_S,
	ARC_INS_LR,
	ARC_INS_LSR,
	ARC_INS_LSR_F,
	ARC_INS_MAX,
	ARC_INS_MAX_F,
	ARC_INS_MIN,
	ARC_INS_MIN_F,
	ARC_INS_MOV_S_NE,
	ARC_INS_MOV,
	ARC_INS_MOV_F,
	ARC_INS_MPYMU,
	ARC_INS_MPYMU_F,
	ARC_INS_MPYM,
	ARC_INS_MPYM_F,
	ARC_INS_MPY,
	ARC_INS_MPY_F,
	ARC_INS_NORMH_F,
	ARC_INS_NORMH,
	ARC_INS_NORM_F,
	ARC_INS_NORM,
	ARC_INS_OR,
	ARC_INS_OR_F,
	ARC_INS_POP_S,
	ARC_INS_PUSH_S,
	ARC_INS_ROR,
	ARC_INS_ROR_F,
	ARC_INS_RSUB,
	ARC_INS_RSUB_F,
	ARC_INS_SBC,
	ARC_INS_SBC_F,
	ARC_INS_SETEQ,
	ARC_INS_SETEQ_F,
	ARC_INS_SEXB_F,
	ARC_INS_SEXB,
	ARC_INS_SEXH_F,
	ARC_INS_SEXH,
	ARC_INS_STB_S,
	ARC_INS_ST_S,
	ARC_INS_STB_AB,
	ARC_INS_STB_AW,
	ARC_INS_STB_DI_AB,
	ARC_INS_STB_DI_AW,
	ARC_INS_STB_DI,
	ARC_INS_STB,
	ARC_INS_STH_AB,
	ARC_INS_STH_AW,
	ARC_INS_STH_DI_AB,
	ARC_INS_STH_DI_AW,
	ARC_INS_STH_DI,
	ARC_INS_STH_S,
	ARC_INS_STH,
	ARC_INS_ST_AB,
	ARC_INS_ST_AW,
	ARC_INS_ST_DI_AB,
	ARC_INS_ST_DI_AW,
	ARC_INS_ST_DI,
	ARC_INS_ST,
	ARC_INS_SUB1,
	ARC_INS_SUB1_F,
	ARC_INS_SUB2,
	ARC_INS_SUB2_F,
	ARC_INS_SUB3,
	ARC_INS_SUB3_F,
	ARC_INS_SUB,
	ARC_INS_SUB_F,
	ARC_INS_XOR,
	ARC_INS_XOR_F,

	// clang-format on
	// generated content <ARCGenCSInsnEnum.inc> end
} arc_insn;

//> Group of ARC instructions
typedef enum arc_insn_group {
	ARC_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	/// Generic groups
	/// all jump instructions (conditional+direct+indirect jumps)
	ARC_GRP_JUMP, ///< = CS_GRP_JUMP
	/// all call instructions
	ARC_GRP_CALL, ///< = CS_GRP_CALL
	/// all return instructions
	ARC_GRP_RET, ///< = CS_GRP_RET
	/// all relative branching instructions
	ARC_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE

	ARC_GRP_ENDING,
} arc_insn_group;

#ifdef __cplusplus
}
#endif

#endif