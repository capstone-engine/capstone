#ifndef CAPSTONE_ALPHA_H
#define CAPSTONE_ALPHA_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "cs_operand.h"
#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

#define NUM_ALPHA_OPS 3

//> Operand type for instruction's operands
typedef enum alpha_op_type {
	ALPHA_OP_INVALID = CS_OP_INVALID, ///< CS_OP_INVALID (Uninitialized).
	ALPHA_OP_REG = CS_OP_REG,	    ///< CS_OP_REG (Register operand).
	ALPHA_OP_IMM = CS_OP_IMM,	    ///< CS_OP_IMM (Immediate operand).
} alpha_op_type;

// Instruction operand
typedef struct cs_alpha_op {
	alpha_op_type type; // operand type
	union {
		unsigned int reg; // register value for REG operand
		int32_t imm; // immediate value for IMM operand
	};
	enum cs_ac_type access;
} cs_alpha_op;

// Instruction structure
typedef struct cs_alpha {
	// Number of operands of this instruction,
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_alpha_op operands[NUM_ALPHA_OPS]; // operands for this instruction.
} cs_alpha;


//> Alpha registers
typedef enum alpha_reg {
	// generated content <AlphaGenCSRegEnum.inc> begin
	// clang-format off

	Alpha_REG_INVALID = 0,
	Alpha_REG_F0 = 1,
	Alpha_REG_F1 = 2,
	Alpha_REG_F2 = 3,
	Alpha_REG_F3 = 4,
	Alpha_REG_F4 = 5,
	Alpha_REG_F5 = 6,
	Alpha_REG_F6 = 7,
	Alpha_REG_F7 = 8,
	Alpha_REG_F8 = 9,
	Alpha_REG_F9 = 10,
	Alpha_REG_F10 = 11,
	Alpha_REG_F11 = 12,
	Alpha_REG_F12 = 13,
	Alpha_REG_F13 = 14,
	Alpha_REG_F14 = 15,
	Alpha_REG_F15 = 16,
	Alpha_REG_F16 = 17,
	Alpha_REG_F17 = 18,
	Alpha_REG_F18 = 19,
	Alpha_REG_F19 = 20,
	Alpha_REG_F20 = 21,
	Alpha_REG_F21 = 22,
	Alpha_REG_F22 = 23,
	Alpha_REG_F23 = 24,
	Alpha_REG_F24 = 25,
	Alpha_REG_F25 = 26,
	Alpha_REG_F26 = 27,
	Alpha_REG_F27 = 28,
	Alpha_REG_F28 = 29,
	Alpha_REG_F29 = 30,
	Alpha_REG_F30 = 31,
	Alpha_REG_F31 = 32,
	Alpha_REG_R0 = 33,
	Alpha_REG_R1 = 34,
	Alpha_REG_R2 = 35,
	Alpha_REG_R3 = 36,
	Alpha_REG_R4 = 37,
	Alpha_REG_R5 = 38,
	Alpha_REG_R6 = 39,
	Alpha_REG_R7 = 40,
	Alpha_REG_R8 = 41,
	Alpha_REG_R9 = 42,
	Alpha_REG_R10 = 43,
	Alpha_REG_R11 = 44,
	Alpha_REG_R12 = 45,
	Alpha_REG_R13 = 46,
	Alpha_REG_R14 = 47,
	Alpha_REG_R15 = 48,
	Alpha_REG_R16 = 49,
	Alpha_REG_R17 = 50,
	Alpha_REG_R18 = 51,
	Alpha_REG_R19 = 52,
	Alpha_REG_R20 = 53,
	Alpha_REG_R21 = 54,
	Alpha_REG_R22 = 55,
	Alpha_REG_R23 = 56,
	Alpha_REG_R24 = 57,
	Alpha_REG_R25 = 58,
	Alpha_REG_R26 = 59,
	Alpha_REG_R27 = 60,
	Alpha_REG_R28 = 61,
	Alpha_REG_R29 = 62,
	Alpha_REG_R30 = 63,
	Alpha_REG_R31 = 64,
	Alpha_REG_ENDING, // 65

	// clang-format on
	// generated content <AlphaGenCSRegEnum.inc> end
} alpha_reg;

//> Alpha instruction
typedef enum alpha_insn {
	// generated content <AlphaGenCSInsnEnum.inc:GET_INSTR_ENUM> begin
	// clang-format off

	Alpha_INS_INVALID,
	Alpha_INS_ADDL,
	Alpha_INS_ADDQ,
	Alpha_INS_ADDSsSU,
	Alpha_INS_ADDTsSU,
	Alpha_INS_AND,
	Alpha_INS_BEQ,
	Alpha_INS_BGE,
	Alpha_INS_BGT,
	Alpha_INS_BIC,
	Alpha_INS_BIS,
	Alpha_INS_BLBC,
	Alpha_INS_BLBS,
	Alpha_INS_BLE,
	Alpha_INS_BLT,
	Alpha_INS_BNE,
	Alpha_INS_BR,
	Alpha_INS_BSR,
	Alpha_INS_CMOVEQ,
	Alpha_INS_CMOVGE,
	Alpha_INS_CMOVGT,
	Alpha_INS_CMOVLBC,
	Alpha_INS_CMOVLBS,
	Alpha_INS_CMOVLE,
	Alpha_INS_CMOVLT,
	Alpha_INS_CMOVNE,
	Alpha_INS_CMPBGE,
	Alpha_INS_CMPEQ,
	Alpha_INS_CMPLE,
	Alpha_INS_CMPLT,
	Alpha_INS_CMPTEQsSU,
	Alpha_INS_CMPTLEsSU,
	Alpha_INS_CMPTLTsSU,
	Alpha_INS_CMPTUNsSU,
	Alpha_INS_CMPULE,
	Alpha_INS_CMPULT,
	Alpha_INS_COND_BRANCH,
	Alpha_INS_CPYSE,
	Alpha_INS_CPYSN,
	Alpha_INS_CPYS,
	Alpha_INS_CTLZ,
	Alpha_INS_CTPOP,
	Alpha_INS_CTTZ,
	Alpha_INS_CVTQSsSUI,
	Alpha_INS_CVTQTsSUI,
	Alpha_INS_CVTSTsS,
	Alpha_INS_CVTTQsSVC,
	Alpha_INS_CVTTSsSUI,
	Alpha_INS_DIVSsSU,
	Alpha_INS_DIVTsSU,
	Alpha_INS_ECB,
	Alpha_INS_EQV,
	Alpha_INS_EXCB,
	Alpha_INS_EXTBL,
	Alpha_INS_EXTLH,
	Alpha_INS_EXTLL,
	Alpha_INS_EXTQH,
	Alpha_INS_EXTQL,
	Alpha_INS_EXTWH,
	Alpha_INS_EXTWL,
	Alpha_INS_FBEQ,
	Alpha_INS_FBGE,
	Alpha_INS_FBGT,
	Alpha_INS_FBLE,
	Alpha_INS_FBLT,
	Alpha_INS_FBNE,
	Alpha_INS_FCMOVEQ,
	Alpha_INS_FCMOVGE,
	Alpha_INS_FCMOVGT,
	Alpha_INS_FCMOVLE,
	Alpha_INS_FCMOVLT,
	Alpha_INS_FCMOVNE,
	Alpha_INS_FETCH,
	Alpha_INS_FETCH_M,
	Alpha_INS_FTOIS,
	Alpha_INS_FTOIT,
	Alpha_INS_INSBL,
	Alpha_INS_INSLH,
	Alpha_INS_INSLL,
	Alpha_INS_INSQH,
	Alpha_INS_INSQL,
	Alpha_INS_INSWH,
	Alpha_INS_INSWL,
	Alpha_INS_ITOFS,
	Alpha_INS_ITOFT,
	Alpha_INS_JMP,
	Alpha_INS_JSR,
	Alpha_INS_JSR_COROUTINE,
	Alpha_INS_LDA,
	Alpha_INS_LDAH,
	Alpha_INS_LDBU,
	Alpha_INS_LDL,
	Alpha_INS_LDL_L,
	Alpha_INS_LDQ,
	Alpha_INS_LDQ_L,
	Alpha_INS_LDQ_U,
	Alpha_INS_LDS,
	Alpha_INS_LDT,
	Alpha_INS_LDWU,
	Alpha_INS_MB,
	Alpha_INS_MSKBL,
	Alpha_INS_MSKLH,
	Alpha_INS_MSKLL,
	Alpha_INS_MSKQH,
	Alpha_INS_MSKQL,
	Alpha_INS_MSKWH,
	Alpha_INS_MSKWL,
	Alpha_INS_MULL,
	Alpha_INS_MULQ,
	Alpha_INS_MULSsSU,
	Alpha_INS_MULTsSU,
	Alpha_INS_ORNOT,
	Alpha_INS_RC,
	Alpha_INS_RET,
	Alpha_INS_RPCC,
	Alpha_INS_RS,
	Alpha_INS_S4ADDL,
	Alpha_INS_S4ADDQ,
	Alpha_INS_S4SUBL,
	Alpha_INS_S4SUBQ,
	Alpha_INS_S8ADDL,
	Alpha_INS_S8ADDQ,
	Alpha_INS_S8SUBL,
	Alpha_INS_S8SUBQ,
	Alpha_INS_SEXTB,
	Alpha_INS_SEXTW,
	Alpha_INS_SLL,
	Alpha_INS_SQRTSsSU,
	Alpha_INS_SQRTTsSU,
	Alpha_INS_SRA,
	Alpha_INS_SRL,
	Alpha_INS_STB,
	Alpha_INS_STL,
	Alpha_INS_STL_C,
	Alpha_INS_STQ,
	Alpha_INS_STQ_C,
	Alpha_INS_STQ_U,
	Alpha_INS_STS,
	Alpha_INS_STT,
	Alpha_INS_STW,
	Alpha_INS_SUBL,
	Alpha_INS_SUBQ,
	Alpha_INS_SUBSsSU,
	Alpha_INS_SUBTsSU,
	Alpha_INS_TRAPB,
	Alpha_INS_UMULH,
	Alpha_INS_WH64,
	Alpha_INS_WH64EN,
	Alpha_INS_WMB,
	Alpha_INS_XOR,
	Alpha_INS_ZAPNOT,

	// clang-format on
	// generated content <AlphaGenCSInsnEnum.inc:GET_INSTR_ENUM> end
    ALPHA_INS_ENDING, // <-- mark the end of the list of instructions
} alpha_insn;

//> Group of Alpha instructions
typedef enum alpha_insn_group {
	Alpha_GRP_INVALID, ///< = CS_GRP_INVALID
	//> Generic groups
	Alpha_GRP_CALL, ///< = CS_GRP_CALL
	Alpha_GRP_JUMP, ///< = CS_GRP_JUMP
	Alpha_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE
	Alpha_GRP_ENDING, ///< = mark the end of the list of groups
} alpha_insn_group;

#ifdef __cplusplus
}
#endif

#endif
