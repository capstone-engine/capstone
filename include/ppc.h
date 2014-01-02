#ifndef CS_PPC_H
#define CS_PPC_H

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>


//> PPC branch codes for some branch instructions
typedef enum ppc_bc {
  PPC_BC_LT       = (0 << 5) | 12,
  PPC_BC_LE       = (1 << 5) |  4,
  PPC_BC_EQ       = (2 << 5) | 12,
  PPC_BC_GE       = (0 << 5) |  4,
  PPC_BC_GT       = (1 << 5) | 12,
  PPC_BC_NE       = (2 << 5) |  4,
  PPC_BC_UN       = (3 << 5) | 12,
  PPC_BC_NU       = (3 << 5) |  4,
  PPC_BC_LT_MINUS = (0 << 5) | 14,
  PPC_BC_LE_MINUS = (1 << 5) |  6,
  PPC_BC_EQ_MINUS = (2 << 5) | 14,
  PPC_BC_GE_MINUS = (0 << 5) |  6,
  PPC_BC_GT_MINUS = (1 << 5) | 14,
  PPC_BC_NE_MINUS = (2 << 5) |  6,
  PPC_BC_UN_MINUS = (3 << 5) | 14,
  PPC_BC_NU_MINUS = (3 << 5) |  6,
  PPC_BC_LT_PLUS  = (0 << 5) | 15,
  PPC_BC_LE_PLUS  = (1 << 5) |  7,
  PPC_BC_EQ_PLUS  = (2 << 5) | 15,
  PPC_BC_GE_PLUS  = (0 << 5) |  7,
  PPC_BC_GT_PLUS  = (1 << 5) | 15,
  PPC_BC_NE_PLUS  = (2 << 5) |  7,
  PPC_BC_UN_PLUS  = (3 << 5) | 15,
  PPC_BC_NU_PLUS  = (3 << 5) |  7
} ppc_bc;

//> Operand type for instruction's operands
typedef enum ppc_op_type {
	PPC_OP_INVALID = 0,	// Uninitialized.
	PPC_OP_REG,	// Register operand.
	PPC_OP_IMM,	// Immediate operand.
	PPC_OP_MEM,	// Memory operand
} ppc_op_type;

// Instruction's operand referring to memory
// This is associated with PPC_OP_MEM operand type above
typedef struct ppc_op_mem {
	unsigned int base;	// base register
	int32_t disp;	// displacement/offset value
} ppc_op_mem;

// Instruction operand
typedef struct cs_ppc_op {
	ppc_op_type type;	// operand type
	union {
		unsigned int reg;	// register value for REG operand
		int32_t imm;		// immediate value for C-IMM or IMM operand
		ppc_op_mem mem;		// base/disp value for MEM operand
	};
} cs_ppc_op;

// Instruction structure
typedef struct cs_ppc {
	// branch code for branch instructions
	ppc_bc cc;

	// if this is True, then this 'dot' insn updates CR0
	bool update_cr0;

	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_ppc_op operands[8]; // operands for this instruction.
} cs_ppc;

//> PPC registers
typedef enum ppc_reg {
	PPC_REG_INVALID = 0,

	// General purpose registers

	PPC_REG_MAX,   // <-- mark the end of the list of registers
} ppc_reg;

//> PPC instruction
typedef enum ppc_insn {
	PPC_INS_INVALID = 0,

	PPC_INS_MAX,   // <-- mark the end of the list of instructions
} ppc_insn;

//> Group of PPC instructions
typedef enum ppc_insn_group {
	PPC_GRP_INVALID = 0,

	PPC_GRP_JUMP,	// all jump instructions (conditional+direct+indirect jumps)

	PPC_GRP_MAX,   // <-- mark the end of the list of groups
} ppc_insn_group;

#ifdef __cplusplus
}
#endif

#endif
