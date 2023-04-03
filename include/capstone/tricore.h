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
#include "./inc/TriCoreGenCSRegEnum.inc"
} tricore_reg;

//> TriCore instruction
typedef enum tricore_insn {
	TriCore_INS_INVALID = 0,
#include "./inc/TriCoreGenCSInsnEnum.inc"
	TriCore_INS_ENDING,   // <-- mark the end of the list of instructions
} tricore_insn;

//> Group of TriCore instructions
typedef enum tricore_insn_group {
	TriCore_GRP_INVALID,	///< = CS_GRP_INVALID
	//> Generic groups
	TriCore_GRP_CALL,	///< = CS_GRP_CALL
	TriCore_GRP_JUMP,	///< = CS_GRP_JUMP
	TriCore_GRP_ENDING,	///< = mark the end of the list of groups
} tricore_insn_group;

#ifdef __cplusplus
}
#endif

#endif
