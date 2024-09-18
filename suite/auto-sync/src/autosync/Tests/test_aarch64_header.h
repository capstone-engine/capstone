// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef CAPSTONE_AARCH64_H
#define CAPSTONE_AARCH64_H

#include "cs_operand.h"

inline static unsigned AArch64CC_getNZCVToSatisfyCondCode(AArch64CC_CondCode Code)
{
	// NZCV flags encoded as expected by ccmp instructions, ARMv8 ISA 5.5.7.
	enum { N = 8, Z = 4, C = 2, V = 1 };
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case AArch64CC_EQ:
		return Z; // Z == 1
	}
}

typedef union {
	aarch64_dbnxs dbnxs;
	aarch64_exactfpimm exactfpimm;
} aarch64_sysop_imm;

typedef enum aarch64_op_type {
	AArch64_OP_SYSALIAS = CS_OP_SPECIAL + 27, // Equal                      Equal
	AArch64_OP_SYSALIASI,
	AArch64_OP_SYSALIASII = 0,
	AArch64_OP_SYSALIASIII, // Comment
} aarch64_op_type;

typedef enum aarch64_op_type_upper {
	AARCH64_OP_SYSALIAS = CS_OP_SPECIAL + 27, // Equal                      Equal
	AARCH64_OP_SYSALIASI,
	AARCH64_OP_SYSALIASII = 0,
	AARCH64_OP_SYSALIASIII, // Comment
} aarch64_op_type_upper;

#define NUM_AARCH64_OPS 8

/// Instruction structure
typedef struct cs_aarch64 {
  AArch64CC_CondCode cc;	     ///< conditional code for this insn
  bool update_flags; ///< does this insn update flags?
  bool post_index;   ///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
  bool is_doing_sme; ///< True if a SME operand is currently edited.

  /// Number of operands of this instruction,
  /// or 0 when instruction has no operand.
  uint8_t op_count;

  cs_aarch64_op operands[NUM_AARCH64_OPS]; ///< operands for this instruction.
} cs_aarch64;

#endif
