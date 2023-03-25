#ifndef CAPSTONE_TRICORE_H
#define CAPSTONE_TRICORE_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> Operand type for instruction's operands
typedef enum tricore_op_type {
	TRICORE_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	TRICORE_OP_REG, // = CS_OP_REG (Register operand).
	TRICORE_OP_IMM, // = CS_OP_IMM (Immediate operand).
	TRICORE_OP_MEM, // = CS_OP_MEM (Memory operand).
} tricore_op_type;

// Instruction's operand referring to memory
// This is associated with TRICORE_OP_MEM operand type above
typedef struct tricore_op_mem {
	uint8_t base;	// base register
	int32_t disp;	// displacement/offset value
} tricore_op_mem;

// Instruction operand
typedef struct cs_tricore_op {
	tricore_op_type type;	// operand type
	union {
		unsigned int reg;	// register value for REG operand
		int32_t imm;		// immediate value for IMM operand
		tricore_op_mem mem;		// base/disp value for MEM operand
	};
} cs_tricore_op;

// Instruction structure
typedef struct cs_tricore {
	// Number of operands of this instruction,
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_tricore_op operands[8]; // operands for this instruction.
} cs_tricore;

//> TriCore registers
typedef enum tricore_reg {
	TriCore_REG_INVALID = 0,
	TriCore_REG_FCX = 1,
	TriCore_REG_PC = 2,
	TriCore_REG_PCXI = 3,
	TriCore_REG_PSW = 4,
	TriCore_REG_A0 = 5,
	TriCore_REG_A1 = 6,
	TriCore_REG_A2 = 7,
	TriCore_REG_A3 = 8,
	TriCore_REG_A4 = 9,
	TriCore_REG_A5 = 10,
	TriCore_REG_A6 = 11,
	TriCore_REG_A7 = 12,
	TriCore_REG_A8 = 13,
	TriCore_REG_A9 = 14,
	TriCore_REG_A10 = 15,
	TriCore_REG_A11 = 16,
	TriCore_REG_A12 = 17,
	TriCore_REG_A13 = 18,
	TriCore_REG_A14 = 19,
	TriCore_REG_A15 = 20,
	TriCore_REG_D0 = 21,
	TriCore_REG_D1 = 22,
	TriCore_REG_D2 = 23,
	TriCore_REG_D3 = 24,
	TriCore_REG_D4 = 25,
	TriCore_REG_D5 = 26,
	TriCore_REG_D6 = 27,
	TriCore_REG_D7 = 28,
	TriCore_REG_D8 = 29,
	TriCore_REG_D9 = 30,
	TriCore_REG_D10 = 31,
	TriCore_REG_D11 = 32,
	TriCore_REG_D12 = 33,
	TriCore_REG_D13 = 34,
	TriCore_REG_D14 = 35,
	TriCore_REG_D15 = 36,
	TriCore_REG_E0 = 37,
	TriCore_REG_E2 = 38,
	TriCore_REG_E4 = 39,
	TriCore_REG_E6 = 40,
	TriCore_REG_E8 = 41,
	TriCore_REG_E10 = 42,
	TriCore_REG_E12 = 43,
	TriCore_REG_E14 = 44,
	TriCore_REG_P0 = 45,
	TriCore_REG_P2 = 46,
	TriCore_REG_P4 = 47,
	TriCore_REG_P6 = 48,
	TriCore_REG_P8 = 49,
	TriCore_REG_P10 = 50,
	TriCore_REG_P12 = 51,
	TriCore_REG_P14 = 52,
	TriCore_REG_A0_A1 = 53,
	TriCore_REG_A2_A3 = 54,
	TriCore_REG_A4_A5 = 55,
	TriCore_REG_A6_A7 = 56,
	TriCore_REG_A8_A9 = 57,
	TriCore_REG_A10_A11 = 58,
	TriCore_REG_A12_A13 = 59,
	TriCore_REG_A14_A15 = 60,

	TriCore_REG_ENDING,	// <-- mark the end of the list of registers
} tricore_reg;

//> TriCore instruction
typedef enum tricore_insn {
	TriCore_INS_INVALID = 0,

#include "./inc/TriCoreGenCSInsnEnum.inc"

	TriCore_INS_ENDING,   // <-- mark the end of the list of instructions

	TriCore_GRP_CALL,	///< = CS_GRP_CALL
	TriCore_GRP_JUMP,	///< = CS_GRP_JUMP
	TriCore_GRP_INVALID, ///< = CS_GRP_INVALID
	TriCore_GRP_ENDING,	 ///< = CS_GRP_ENDING
} tricore_insn;

//> Group of TriCore instructions
typedef enum tricore_insn_group {
	TRICORE_GRP_INVALID = 0, // = CS_GRP_INVALID

	//> Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	TRICORE_GRP_JUMP,	// = CS_GRP_JUMP

	TRICORE_GRP_ENDING,   // <-- mark the end of the list of groups
} tricore_insn_group;

#ifdef __cplusplus
}
#endif

#endif
