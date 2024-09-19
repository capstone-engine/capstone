#ifndef CAPSTONE_XTENSA_H
#define CAPSTONE_XTENSA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cs_operand.h"
#include "platform.h"

/// Xtensa registers
typedef enum xtensa_reg {
	// generated content <XtensaGenCSRegEnum.inc> begin
	// clang-format off

	XTENSA_REG_INVALID = 0,
	XTENSA_REG_SAR = 1,
	XTENSA_REG_SP = 2,
	XTENSA_REG_A0 = 3,
	XTENSA_REG_A2 = 4,
	XTENSA_REG_A3 = 5,
	XTENSA_REG_A4 = 6,
	XTENSA_REG_A5 = 7,
	XTENSA_REG_A6 = 8,
	XTENSA_REG_A7 = 9,
	XTENSA_REG_A8 = 10,
	XTENSA_REG_A9 = 11,
	XTENSA_REG_A10 = 12,
	XTENSA_REG_A11 = 13,
	XTENSA_REG_A12 = 14,
	XTENSA_REG_A13 = 15,
	XTENSA_REG_A14 = 16,
	XTENSA_REG_A15 = 17,
	XTENSA_REG_ENDING, // 18

	// clang-format on
	// generated content <XtensaGenCSRegEnum.inc> end
} xtensa_reg;

/// Xtensa registers
typedef enum xtensa_insn {
	// generated content <XtensaGenCSInsnEnum.inc> begin
	// clang-format off

	XTENSA_INS_INVALID,
	XTENSA_INS_ABS,
	XTENSA_INS_ADD,
	XTENSA_INS_ADDI,
	XTENSA_INS_ADDMI,
	XTENSA_INS_ADDX2,
	XTENSA_INS_ADDX4,
	XTENSA_INS_ADDX8,
	XTENSA_INS_AND,
	XTENSA_INS_BALL,
	XTENSA_INS_BANY,
	XTENSA_INS_BBC,
	XTENSA_INS_BBCI,
	XTENSA_INS_BBS,
	XTENSA_INS_BBSI,
	XTENSA_INS_BEQ,
	XTENSA_INS_BEQI,
	XTENSA_INS_BEQZ,
	XTENSA_INS_BGE,
	XTENSA_INS_BGEI,
	XTENSA_INS_BGEU,
	XTENSA_INS_BGEUI,
	XTENSA_INS_BGEZ,
	XTENSA_INS_BLT,
	XTENSA_INS_BLTI,
	XTENSA_INS_BLTU,
	XTENSA_INS_BLTUI,
	XTENSA_INS_BLTZ,
	XTENSA_INS_BNALL,
	XTENSA_INS_BNE,
	XTENSA_INS_BNEI,
	XTENSA_INS_BNEZ,
	XTENSA_INS_BNONE,
	XTENSA_INS_CALL0,
	XTENSA_INS_CALLX0,
	XTENSA_INS_DSYNC,
	XTENSA_INS_ESYNC,
	XTENSA_INS_EXTUI,
	XTENSA_INS_EXTW,
	XTENSA_INS_ISYNC,
	XTENSA_INS_J,
	XTENSA_INS_JX,
	XTENSA_INS_L16SI,
	XTENSA_INS_L16UI,
	XTENSA_INS_L32I,
	XTENSA_INS_L32R,
	XTENSA_INS_L8UI,
	XTENSA_INS_MEMW,
	XTENSA_INS_MOVEQZ,
	XTENSA_INS_MOVGEZ,
	XTENSA_INS_MOVI,
	XTENSA_INS_MOVLTZ,
	XTENSA_INS_MOVNEZ,
	XTENSA_INS_NEG,
	XTENSA_INS_NOP,
	XTENSA_INS_OR,
	XTENSA_INS_RET,
	XTENSA_INS_RSR,
	XTENSA_INS_RSYNC,
	XTENSA_INS_S16I,
	XTENSA_INS_S32I,
	XTENSA_INS_S8I,
	XTENSA_INS_SLL,
	XTENSA_INS_SLLI,
	XTENSA_INS_SRA,
	XTENSA_INS_SRAI,
	XTENSA_INS_SRC,
	XTENSA_INS_SRL,
	XTENSA_INS_SRLI,
	XTENSA_INS_SSA8L,
	XTENSA_INS_SSAI,
	XTENSA_INS_SSL,
	XTENSA_INS_SSR,
	XTENSA_INS_SUB,
	XTENSA_INS_SUBX2,
	XTENSA_INS_SUBX4,
	XTENSA_INS_SUBX8,
	XTENSA_INS_WSR,
	XTENSA_INS_XOR,
	XTENSA_INS_XSR,

	// clang-format on
	// generated content <XtensaGenCSInsnEnum.inc> end
} xtensa_insn;

typedef enum xtensa_feature {
	XTENSA_GRP_INVALID = 0,
	XTENSA_GRP_CALL,
	XTENSA_GRP_JUMP,
	XTENSA_GRP_RET,
	// generated content <XtensaGenCSFeatureEnum.inc> begin
	// clang-format off

	XTENSA_FEATURE_HASDENSITY = 128,

	// clang-format on
	// generated content <XtensaGenCSFeatureEnum.inc> end
	XTENSA_GRP_ENDING, ///< mark the end of the list of features
} xtensa_feature;

typedef enum cs_xtensa_op_type {
	XTENSA_OP_INVALID = CS_OP_INVALID, ///< = (Uninitialized).
	XTENSA_OP_REG = CS_OP_REG,	   ///< = (Register operand).
	XTENSA_OP_IMM = CS_OP_IMM,	   ///< = (Immediate operand).
	XTENSA_OP_MEM = CS_OP_MEM,	   ///< = (Memory operand).
	XTENSA_OP_MEM_REG = CS_OP_MEM_REG, ///< = (Memory Register operand).
	XTENSA_OP_MEM_IMM = CS_OP_MEM_IMM, ///< = (Memory Immediate operand).
	XTENSA_OP_L32R,			   ///< = (L32R Target)
} cs_xtensa_op_type;

typedef struct cs_xtensa_op_mem {
	uint8_t base;
	uint8_t disp;
} cs_xtensa_op_mem;

typedef struct cs_xtensa_operand {
	uint8_t type;
	uint8_t access;

	union {
		uint8_t reg;
		int32_t imm;
		cs_xtensa_op_mem mem;
	};
} cs_xtensa_op;

#define MAX_XTENSA_OPS 8

typedef struct cs_xtensa {
	uint8_t op_count;
	cs_xtensa_op operands[MAX_XTENSA_OPS];
} cs_xtensa;

#ifdef __cplusplus
}
#endif

#endif
