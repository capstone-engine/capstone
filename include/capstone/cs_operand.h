/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_OPERAND_H
#define CS_OPERAND_H

/// Common instruction operand types - to be consistent across all architectures.
typedef enum cs_op_type {
	CS_OP_INVALID = 0, ///< uninitialized/invalid operand.
	CS_OP_REG = 1,	   ///< Register operand.
	CS_OP_IMM = 2,	   ///< Immediate operand.
	CS_OP_FP = 3,	   ///< Floating-Point operand.
	CS_OP_PRED = 4,	   ///< Predicate operand.
	CS_OP_RESERVED_5 = 5,
	CS_OP_RESERVED_6 = 6,
	CS_OP_RESERVED_7 = 7,
	CS_OP_RESERVED_8 = 8,
	CS_OP_RESERVED_9 = 9,
	CS_OP_RESERVED_10 = 10,
	CS_OP_RESERVED_11 = 11,
	CS_OP_RESERVED_12 = 12,
	CS_OP_RESERVED_13 = 13,
	CS_OP_RESERVED_14 = 14,
	CS_OP_RESERVED_15 = 15,
	CS_OP_SPECIAL = 0x10, ///< Special operands from archs
	CS_OP_BOUND = 0x40, ///< Operand is associated with a previous operand. Used by AArch64 for SME operands.
	CS_OP_MEM = 0x80, ///< Memory operand. Can be ORed with another operand type.
	CS_OP_MEM_REG = CS_OP_MEM | CS_OP_REG,	   ///< Memory referencing register operand.
	CS_OP_MEM_IMM = CS_OP_MEM | CS_OP_IMM,	   ///< Memory referencing immediate operand.

} cs_op_type;

/// Common instruction operand access types - to be consistent across all architectures.
/// It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
typedef enum cs_ac_type {
	CS_AC_INVALID = 0,    ///< Uninitialized/invalid access type.
	CS_AC_READ = 1 << 0,  ///< Operand read from memory or register.
	CS_AC_WRITE = 1 << 1, ///< Operand write to memory or register.
	CS_AC_READ_WRITE =
		CS_AC_READ |
		CS_AC_WRITE, ///< Operand reads and writes from/to memory or register.
} cs_ac_type;

#endif			     // CS_OPERAND_H
