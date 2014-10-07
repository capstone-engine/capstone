#ifndef CAPSTONE_GENERIC_H
#define CAPSTONE_GENERIC_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

typedef enum generic_op_type {
	GENERIC_OP_INVALID = 0, // Uninitialized.
	GENERIC_OP_MEM, // Memory operand.
	GENERIC_OP_IMM, // Immediate operand.
	GENERIC_OP_REG, // Register operand.
	GENERIC_OP_FP,  // Floating-Point immediate operand.
	GENERIC_OP_ARCH_SPECIFIC, // Last value. Arch-specific operand type identifiers start here.
} generic_op_type;

typedef enum generic_insn_group {
	GENERIC_GRP_INVALID = 0, // Uninitialized.
	GENERIC_GRP_JUMP, // all jump instructions (conditional+direct+indirect jumps).
	GENERIC_GRP_ARCH_SPECIFIC, // Last value. Arch-specific operand type identifiers start here.
} generic_insn_group;

#endif
