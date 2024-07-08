// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef CAPSTONE_ARM64_H
#define CAPSTONE_ARM64_H

#include <capstone/aarch64.h>
#include "cs_operand.h"

inline static unsigned ARM64CC_getNZCVToSatisfyCondCode(ARM64CC_CondCode Code)
{
	enum { N = 8, Z = 4, C = 2, V = 1 };
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case ARM64CC_EQ:
		return Z; // Z == 1
	}
}

typedef aarch64_sysop_imm arm64_sysop_imm;

typedef enum {
	ARM64_OP_SYSALIAS = AArch64_OP_SYSALIAS,
	ARM64_OP_SYSALIASI = AArch64_OP_SYSALIASI,
	ARM64_OP_SYSALIASII = AArch64_OP_SYSALIASII,
	ARM64_OP_SYSALIASIII = AArch64_OP_SYSALIASIII,
} arm64_op_type;

typedef enum {
	ARM64_OP_SYSALIAS = AARCH64_OP_SYSALIAS,
	ARM64_OP_SYSALIASI = AARCH64_OP_SYSALIASI,
	ARM64_OP_SYSALIASII = AARCH64_OP_SYSALIASII,
	ARM64_OP_SYSALIASIII = AARCH64_OP_SYSALIASIII,
} arm64_op_type_upper;

#define MAX_ARM64_OPS 8

typedef cs_aarch64 cs_arm64;

#endif
