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
	uint8_t index;	// index register
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
	TRICORE_REG_INVALID = 0,

	TRICORE_REG_D0,
	TRICORE_REG_D1,
	TRICORE_REG_D2,
	TRICORE_REG_D3,
	TRICORE_REG_D4,
	TRICORE_REG_D5,
	TRICORE_REG_D6,
	TRICORE_REG_D7,
	TRICORE_REG_D8,
	TRICORE_REG_D9,
	TRICORE_REG_D10,
	TRICORE_REG_D11,
	TRICORE_REG_D12,
	TRICORE_REG_D13,
	TRICORE_REG_D14,
	TRICORE_REG_D15,
	TRICORE_REG_A0,
	TRICORE_REG_A1,
	TRICORE_REG_A2,
	TRICORE_REG_A3,
	TRICORE_REG_A4,
	TRICORE_REG_A5,
	TRICORE_REG_A6,
	TRICORE_REG_A7,
	TRICORE_REG_A8,
	TRICORE_REG_A9,
	TRICORE_REG_A10,
	TRICORE_REG_A11,
	TRICORE_REG_A12,
	TRICORE_REG_A13,
	TRICORE_REG_A14,
	TRICORE_REG_A15,
	TRICORE_REG_E0,
	TRICORE_REG_E2,
	TRICORE_REG_E4,
	TRICORE_REG_E6,
	TRICORE_REG_E8,
	TRICORE_REG_E10,
	TRICORE_REG_E12,
	TRICORE_REG_E14,

	//> control registers
	TRICORE_REG_PSW,
	TRICORE_REG_PCXI,
	TRICORE_REG_PC,
	TRICORE_REG_FCX,

	TRICORE_REG_ENDING,	// <-- mark the end of the list of registers
} tricore_reg;

//> TriCore instruction
typedef enum tricore_insn {
	TRICORE_INS_INVALID = 0,

	TRICORE_INS_ABS,
	TRICORE_INS_ADD,
	TRICORE_INS_AND,
	TRICORE_INS_CALL,
	TRICORE_INS_DEXTR,
	TRICORE_INS_EQ,
	TRICORE_INS_EXTR,
	TRICORE_INS_GE,
	TRICORE_INS_IMASK,
	TRICORE_INS_JNZ,
	TRICORE_INS_JZ,
	TRICORE_INS_J,
	TRICORE_INS_LDBU,
	TRICORE_INS_LDB,
	TRICORE_INS_LDD,
	TRICORE_INS_LDHU,
	TRICORE_INS_LDH,
	TRICORE_INS_LDW,
	TRICORE_INS_LT,
	TRICORE_INS_MOVAA,
	TRICORE_INS_MOVA,
	TRICORE_INS_MOVD,
	TRICORE_INS_MOVH,
	TRICORE_INS_MOVU,
	TRICORE_INS_MOV,
	TRICORE_INS_MUL,
	TRICORE_INS_NAND,
	TRICORE_INS_NE,
	TRICORE_INS_NOR,
	TRICORE_INS_NOT,
	TRICORE_INS_ORN,
	TRICORE_INS_OR_GEU,
	TRICORE_INS_OR_GE,
	TRICORE_INS_OR_LTU,
	TRICORE_INS_OR_LT,
	TRICORE_INS_OR_NE,
	TRICORE_INS_OR,
	TRICORE_INS_RET,
	TRICORE_INS_RSUB,
	TRICORE_INS_SHA,
	TRICORE_INS_SH,
	TRICORE_INS_STA,
	TRICORE_INS_STB,
	TRICORE_INS_STD,
	TRICORE_INS_STH,
	TRICORE_INS_STW,
	TRICORE_INS_SUBA,
	TRICORE_INS_SUBC,
	TRICORE_INS_SUBX,
	TRICORE_INS_SUB,
	TRICORE_INS_Select8,
	TRICORE_INS_XNOR,
	TRICORE_INS_XOR,

	TRICORE_INS_ENDING,   // <-- mark the end of the list of instructions
} tricore_insn;

#ifdef __cplusplus
}
#endif

#endif
