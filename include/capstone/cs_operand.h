/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_OPERAND_H
#define CS_OPERAND_H

#include <stdint.h>

#define MAX_NUM_OP_ENC_ITEMS 8

/// Provides information about an operand's encoding in the instruction
typedef struct cs_operand_encoding {
	/// Specifies how many pieces that form the full operand are encoded in the
	/// instruction separately. For example if count is 2 it means a few bits of
	/// this operand are in one location and the rest on another. If it's 0 then
	/// the operand is NOT encoded anywhere in the instruction.
	uint8_t operand_pieces_count;
	/// The bit positions of each piece that form the full operand in order. If
	/// there is only one piece then there is only one index as well. Likewise
	/// if there are 4 pieces, there are 4 indexes and so on.
	uint8_t indexes[MAX_NUM_OP_ENC_ITEMS];
	/// The bit widths of each piece that form the full operand in order. If
	/// there is only one piece then there is only one size as well. Likewise if
	/// there are 4 pieces, there are 4 sizes and so on.
	uint8_t sizes[MAX_NUM_OP_ENC_ITEMS];
} cs_operand_encoding;

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
	CS_OP_MEM =
		0x80, ///< Memory operand. Can be ORed with another operand type.
	CS_OP_MEM_REG = CS_OP_MEM | CS_OP_REG,	   ///< Memory referenceing register operand.
	CS_OP_MEM_IMM = CS_OP_MEM | CS_OP_IMM,	   ///< Memory referenceing immediate operand.

} cs_op_type;

/// Common instruction operand access types - to be consistent across all architectures.
/// It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
typedef enum cs_ac_type {
	CS_AC_INVALID = 0,    ///< Uninitialized/invalid access type.
	CS_AC_READ = 1 << 0,  ///< Operand read from memory or register.
	CS_AC_WRITE = 1 << 1, ///< Operand write to memory or register.
	CS_AC_READ_WRTE =
		CS_AC_READ |
		CS_AC_WRITE, ///< Operand reads and writes from/to memory or register.
} cs_ac_type;

#endif			     // CS_OPERAND_H
