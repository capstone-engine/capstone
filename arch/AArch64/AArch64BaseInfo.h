/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically translated source file from LLVM. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Only small edits allowed. */
/* For multiple similar edits, please create a Patch for the translator. */

/* Capstone's C++ file translator: */
/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

//===-- AArch64BaseInfo.h - Top level definitions for AArch64 ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone helper functions and enum definitions for
// the AArch64 target useful for the compiler back-end and the MC libraries.
// As such, it deliberately does not include references to LLVM core
// code gen types, passes, etc..
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_AARCH64_UTILS_AARCH64BASEINFO_H
#define LLVM_LIB_TARGET_AARCH64_UTILS_AARCH64BASEINFO_H

// FIXME: Is it easiest to fix this layering violation by moving the .inc
// #includes from AArch64MCTargetDesc.h to here?
#include <capstone/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../MCInstPrinter.h"
#include "AArch64Mapping.h"

#include "../../utils.h"
#include "capstone/arm.h"

#define GET_REGINFO_ENUM
#include "AArch64GenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

inline static unsigned getWRegFromXReg(unsigned Reg)
{
	switch (Reg) {
	case AARCH64_X0:
		return AARCH64_W0;
	case AARCH64_X1:
		return AARCH64_W1;
	case AARCH64_X2:
		return AARCH64_W2;
	case AARCH64_X3:
		return AARCH64_W3;
	case AARCH64_X4:
		return AARCH64_W4;
	case AARCH64_X5:
		return AARCH64_W5;
	case AARCH64_X6:
		return AARCH64_W6;
	case AARCH64_X7:
		return AARCH64_W7;
	case AARCH64_X8:
		return AARCH64_W8;
	case AARCH64_X9:
		return AARCH64_W9;
	case AARCH64_X10:
		return AARCH64_W10;
	case AARCH64_X11:
		return AARCH64_W11;
	case AARCH64_X12:
		return AARCH64_W12;
	case AARCH64_X13:
		return AARCH64_W13;
	case AARCH64_X14:
		return AARCH64_W14;
	case AARCH64_X15:
		return AARCH64_W15;
	case AARCH64_X16:
		return AARCH64_W16;
	case AARCH64_X17:
		return AARCH64_W17;
	case AARCH64_X18:
		return AARCH64_W18;
	case AARCH64_X19:
		return AARCH64_W19;
	case AARCH64_X20:
		return AARCH64_W20;
	case AARCH64_X21:
		return AARCH64_W21;
	case AARCH64_X22:
		return AARCH64_W22;
	case AARCH64_X23:
		return AARCH64_W23;
	case AARCH64_X24:
		return AARCH64_W24;
	case AARCH64_X25:
		return AARCH64_W25;
	case AARCH64_X26:
		return AARCH64_W26;
	case AARCH64_X27:
		return AARCH64_W27;
	case AARCH64_X28:
		return AARCH64_W28;
	case AARCH64_FP:
		return AARCH64_W29;
	case AARCH64_LR:
		return AARCH64_W30;
	case AARCH64_SP:
		return AARCH64_WSP;
	case AARCH64_XZR:
		return AARCH64_WZR;
	}
	// For anything else, return it unchanged.
	return Reg;
}

inline static unsigned getXRegFromWReg(unsigned Reg)
{
	switch (Reg) {
	case AARCH64_W0:
		return AARCH64_X0;
	case AARCH64_W1:
		return AARCH64_X1;
	case AARCH64_W2:
		return AARCH64_X2;
	case AARCH64_W3:
		return AARCH64_X3;
	case AARCH64_W4:
		return AARCH64_X4;
	case AARCH64_W5:
		return AARCH64_X5;
	case AARCH64_W6:
		return AARCH64_X6;
	case AARCH64_W7:
		return AARCH64_X7;
	case AARCH64_W8:
		return AARCH64_X8;
	case AARCH64_W9:
		return AARCH64_X9;
	case AARCH64_W10:
		return AARCH64_X10;
	case AARCH64_W11:
		return AARCH64_X11;
	case AARCH64_W12:
		return AARCH64_X12;
	case AARCH64_W13:
		return AARCH64_X13;
	case AARCH64_W14:
		return AARCH64_X14;
	case AARCH64_W15:
		return AARCH64_X15;
	case AARCH64_W16:
		return AARCH64_X16;
	case AARCH64_W17:
		return AARCH64_X17;
	case AARCH64_W18:
		return AARCH64_X18;
	case AARCH64_W19:
		return AARCH64_X19;
	case AARCH64_W20:
		return AARCH64_X20;
	case AARCH64_W21:
		return AARCH64_X21;
	case AARCH64_W22:
		return AARCH64_X22;
	case AARCH64_W23:
		return AARCH64_X23;
	case AARCH64_W24:
		return AARCH64_X24;
	case AARCH64_W25:
		return AARCH64_X25;
	case AARCH64_W26:
		return AARCH64_X26;
	case AARCH64_W27:
		return AARCH64_X27;
	case AARCH64_W28:
		return AARCH64_X28;
	case AARCH64_W29:
		return AARCH64_FP;
	case AARCH64_W30:
		return AARCH64_LR;
	case AARCH64_WSP:
		return AARCH64_SP;
	case AARCH64_WZR:
		return AARCH64_XZR;
	}
	// For anything else, return it unchanged.
	return Reg;
}

inline static unsigned getXRegFromXRegTuple(unsigned RegTuple)
{
	switch (RegTuple) {
	case AARCH64_X0_X1_X2_X3_X4_X5_X6_X7:
		return AARCH64_X0;
	case AARCH64_X2_X3_X4_X5_X6_X7_X8_X9:
		return AARCH64_X2;
	case AARCH64_X4_X5_X6_X7_X8_X9_X10_X11:
		return AARCH64_X4;
	case AARCH64_X6_X7_X8_X9_X10_X11_X12_X13:
		return AARCH64_X6;
	case AARCH64_X8_X9_X10_X11_X12_X13_X14_X15:
		return AARCH64_X8;
	case AARCH64_X10_X11_X12_X13_X14_X15_X16_X17:
		return AARCH64_X10;
	case AARCH64_X12_X13_X14_X15_X16_X17_X18_X19:
		return AARCH64_X12;
	case AARCH64_X14_X15_X16_X17_X18_X19_X20_X21:
		return AARCH64_X14;
	case AARCH64_X16_X17_X18_X19_X20_X21_X22_X23:
		return AARCH64_X16;
	case AARCH64_X18_X19_X20_X21_X22_X23_X24_X25:
		return AARCH64_X18;
	case AARCH64_X20_X21_X22_X23_X24_X25_X26_X27:
		return AARCH64_X20;
	case AARCH64_X22_X23_X24_X25_X26_X27_X28_FP:
		return AARCH64_X22;
	}
	// For anything else, return it unchanged.
	return RegTuple;
}

static inline unsigned getBRegFromDReg(unsigned Reg)
{
	switch (Reg) {
	case AARCH64_D0:
		return AARCH64_B0;
	case AARCH64_D1:
		return AARCH64_B1;
	case AARCH64_D2:
		return AARCH64_B2;
	case AARCH64_D3:
		return AARCH64_B3;
	case AARCH64_D4:
		return AARCH64_B4;
	case AARCH64_D5:
		return AARCH64_B5;
	case AARCH64_D6:
		return AARCH64_B6;
	case AARCH64_D7:
		return AARCH64_B7;
	case AARCH64_D8:
		return AARCH64_B8;
	case AARCH64_D9:
		return AARCH64_B9;
	case AARCH64_D10:
		return AARCH64_B10;
	case AARCH64_D11:
		return AARCH64_B11;
	case AARCH64_D12:
		return AARCH64_B12;
	case AARCH64_D13:
		return AARCH64_B13;
	case AARCH64_D14:
		return AARCH64_B14;
	case AARCH64_D15:
		return AARCH64_B15;
	case AARCH64_D16:
		return AARCH64_B16;
	case AARCH64_D17:
		return AARCH64_B17;
	case AARCH64_D18:
		return AARCH64_B18;
	case AARCH64_D19:
		return AARCH64_B19;
	case AARCH64_D20:
		return AARCH64_B20;
	case AARCH64_D21:
		return AARCH64_B21;
	case AARCH64_D22:
		return AARCH64_B22;
	case AARCH64_D23:
		return AARCH64_B23;
	case AARCH64_D24:
		return AARCH64_B24;
	case AARCH64_D25:
		return AARCH64_B25;
	case AARCH64_D26:
		return AARCH64_B26;
	case AARCH64_D27:
		return AARCH64_B27;
	case AARCH64_D28:
		return AARCH64_B28;
	case AARCH64_D29:
		return AARCH64_B29;
	case AARCH64_D30:
		return AARCH64_B30;
	case AARCH64_D31:
		return AARCH64_B31;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline unsigned getDRegFromBReg(unsigned Reg)
{
	switch (Reg) {
	case AARCH64_B0:
		return AARCH64_D0;
	case AARCH64_B1:
		return AARCH64_D1;
	case AARCH64_B2:
		return AARCH64_D2;
	case AARCH64_B3:
		return AARCH64_D3;
	case AARCH64_B4:
		return AARCH64_D4;
	case AARCH64_B5:
		return AARCH64_D5;
	case AARCH64_B6:
		return AARCH64_D6;
	case AARCH64_B7:
		return AARCH64_D7;
	case AARCH64_B8:
		return AARCH64_D8;
	case AARCH64_B9:
		return AARCH64_D9;
	case AARCH64_B10:
		return AARCH64_D10;
	case AARCH64_B11:
		return AARCH64_D11;
	case AARCH64_B12:
		return AARCH64_D12;
	case AARCH64_B13:
		return AARCH64_D13;
	case AARCH64_B14:
		return AARCH64_D14;
	case AARCH64_B15:
		return AARCH64_D15;
	case AARCH64_B16:
		return AARCH64_D16;
	case AARCH64_B17:
		return AARCH64_D17;
	case AARCH64_B18:
		return AARCH64_D18;
	case AARCH64_B19:
		return AARCH64_D19;
	case AARCH64_B20:
		return AARCH64_D20;
	case AARCH64_B21:
		return AARCH64_D21;
	case AARCH64_B22:
		return AARCH64_D22;
	case AARCH64_B23:
		return AARCH64_D23;
	case AARCH64_B24:
		return AARCH64_D24;
	case AARCH64_B25:
		return AARCH64_D25;
	case AARCH64_B26:
		return AARCH64_D26;
	case AARCH64_B27:
		return AARCH64_D27;
	case AARCH64_B28:
		return AARCH64_D28;
	case AARCH64_B29:
		return AARCH64_D29;
	case AARCH64_B30:
		return AARCH64_D30;
	case AARCH64_B31:
		return AARCH64_D31;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline bool atomicBarrierDroppedOnZero(unsigned Opcode)
{
	switch (Opcode) {
	case AARCH64_LDADDAB:
	case AARCH64_LDADDAH:
	case AARCH64_LDADDAW:
	case AARCH64_LDADDAX:
	case AARCH64_LDADDALB:
	case AARCH64_LDADDALH:
	case AARCH64_LDADDALW:
	case AARCH64_LDADDALX:
	case AARCH64_LDCLRAB:
	case AARCH64_LDCLRAH:
	case AARCH64_LDCLRAW:
	case AARCH64_LDCLRAX:
	case AARCH64_LDCLRALB:
	case AARCH64_LDCLRALH:
	case AARCH64_LDCLRALW:
	case AARCH64_LDCLRALX:
	case AARCH64_LDEORAB:
	case AARCH64_LDEORAH:
	case AARCH64_LDEORAW:
	case AARCH64_LDEORAX:
	case AARCH64_LDEORALB:
	case AARCH64_LDEORALH:
	case AARCH64_LDEORALW:
	case AARCH64_LDEORALX:
	case AARCH64_LDSETAB:
	case AARCH64_LDSETAH:
	case AARCH64_LDSETAW:
	case AARCH64_LDSETAX:
	case AARCH64_LDSETALB:
	case AARCH64_LDSETALH:
	case AARCH64_LDSETALW:
	case AARCH64_LDSETALX:
	case AARCH64_LDSMAXAB:
	case AARCH64_LDSMAXAH:
	case AARCH64_LDSMAXAW:
	case AARCH64_LDSMAXAX:
	case AARCH64_LDSMAXALB:
	case AARCH64_LDSMAXALH:
	case AARCH64_LDSMAXALW:
	case AARCH64_LDSMAXALX:
	case AARCH64_LDSMINAB:
	case AARCH64_LDSMINAH:
	case AARCH64_LDSMINAW:
	case AARCH64_LDSMINAX:
	case AARCH64_LDSMINALB:
	case AARCH64_LDSMINALH:
	case AARCH64_LDSMINALW:
	case AARCH64_LDSMINALX:
	case AARCH64_LDUMAXAB:
	case AARCH64_LDUMAXAH:
	case AARCH64_LDUMAXAW:
	case AARCH64_LDUMAXAX:
	case AARCH64_LDUMAXALB:
	case AARCH64_LDUMAXALH:
	case AARCH64_LDUMAXALW:
	case AARCH64_LDUMAXALX:
	case AARCH64_LDUMINAB:
	case AARCH64_LDUMINAH:
	case AARCH64_LDUMINAW:
	case AARCH64_LDUMINAX:
	case AARCH64_LDUMINALB:
	case AARCH64_LDUMINALH:
	case AARCH64_LDUMINALW:
	case AARCH64_LDUMINALX:
	case AARCH64_SWPAB:
	case AARCH64_SWPAH:
	case AARCH64_SWPAW:
	case AARCH64_SWPAX:
	case AARCH64_SWPALB:
	case AARCH64_SWPALH:
	case AARCH64_SWPALW:
	case AARCH64_SWPALX:
		return true;
	}
	return false;
}

// The CondCodes constants map directly to the 4-bit encoding of the condition
// field for predicated instructions.
typedef enum CondCode {			// Meaning (integer)          Meaning (floating-point)
	AArch64CC_EQ = 0x0, // Equal                      Equal
	AArch64CC_NE = 0x1, // Not equal                  Not equal, or unordered
	AArch64CC_HS = 0x2, // Unsigned higher or same    >, ==, or unordered
	AArch64CC_LO = 0x3, // Unsigned lower             Less than
	AArch64CC_MI = 0x4, // Minus, negative            Less than
	AArch64CC_PL = 0x5, // Plus, positive or zero     >, ==, or unordered
	AArch64CC_VS = 0x6, // Overflow                   Unordered
	AArch64CC_VC = 0x7, // No overflow                Not unordered
	AArch64CC_HI = 0x8, // Unsigned higher            Greater than, or unordered
	AArch64CC_LS = 0x9, // Unsigned lower or same     Less than or equal
	AArch64CC_GE = 0xa, // Greater than or equal      Greater than or equal
	AArch64CC_LT = 0xb, // Less than                  Less than, or unordered
	AArch64CC_GT = 0xc, // Greater than               Greater than
	AArch64CC_LE = 0xd, // Less than or equal         <, ==, or unordered
	AArch64CC_AL = 0xe, // Always (unconditional)     Always (unconditional)
	AArch64CC_NV = 0xf, // Always (unconditional)     Always (unconditional)
	// Note the NV exists purely to disassemble 0b1111. Execution is "always".
	AArch64CC_Invalid,

	// Common aliases used for SVE.
	AArch64CC_ANY_ACTIVE = AArch64CC_NE,	 // (!Z)
	AArch64CC_FIRST_ACTIVE = AArch64CC_MI, // ( N)
	AArch64CC_LAST_ACTIVE = AArch64CC_LO,	 // (!C)
	AArch64CC_NONE_ACTIVE = AArch64CC_EQ	 // ( Z)
} AArch64_CondCode;

inline static const char *AArch64CC_getCondCodeName(AArch64_CondCode Code)
{
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case AArch64CC_EQ:
		return "eq";
	case AArch64CC_NE:
		return "ne";
	case AArch64CC_HS:
		return "hs";
	case AArch64CC_LO:
		return "lo";
	case AArch64CC_MI:
		return "mi";
	case AArch64CC_PL:
		return "pl";
	case AArch64CC_VS:
		return "vs";
	case AArch64CC_VC:
		return "vc";
	case AArch64CC_HI:
		return "hi";
	case AArch64CC_LS:
		return "ls";
	case AArch64CC_GE:
		return "ge";
	case AArch64CC_LT:
		return "lt";
	case AArch64CC_GT:
		return "gt";
	case AArch64CC_LE:
		return "le";
	case AArch64CC_AL:
		return "al";
	case AArch64CC_NV:
		return "nv";
	}
}

inline static AArch64_CondCode AArch64CC_getInvertedCondCode(AArch64_CondCode Code)
{
	// To reverse a condition it's necessary to only invert the low bit:

	return (AArch64_CondCode)((unsigned)(Code) ^ 0x1);
}

/// Given a condition code, return NZCV flags that would satisfy that condition.
/// The flag bits are in the format expected by the ccmp instructions.
/// Note that many different flag settings can satisfy a given condition code,
/// this function just returns one of them.
inline static unsigned AArch64CC_getNZCVToSatisfyCondCode(AArch64_CondCode Code)
{
	// NZCV flags encoded as expected by ccmp instructions, ARMv8 ISA 5.5.7.
	enum { N = 8, Z = 4, C = 2, V = 1 };
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case AArch64CC_EQ:
		return Z; // Z == 1
	case AArch64CC_NE:
		return 0; // Z == 0
	case AArch64CC_HS:
		return C; // C == 1
	case AArch64CC_LO:
		return 0; // C == 0
	case AArch64CC_MI:
		return N; // N == 1
	case AArch64CC_PL:
		return 0; // N == 0
	case AArch64CC_VS:
		return V; // V == 1
	case AArch64CC_VC:
		return 0; // V == 0
	case AArch64CC_HI:
		return C; // C == 1 && Z == 0
	case AArch64CC_LS:
		return 0; // C == 0 || Z == 1
	case AArch64CC_GE:
		return 0; // N == V
	case AArch64CC_LT:
		return N; // N != V
	case AArch64CC_GT:
		return 0; // Z == 0 && N == V
	case AArch64CC_LE:
		return Z; // Z == 1 || N != V
	}
}

/// Return true if Code is a reflexive relationship:
/// forall x. (CSET Code (CMP x x)) == 1
inline static bool AArch64CC_isReflexive(AArch64_CondCode Code)
{
	switch (Code) {
	case AArch64CC_EQ:
	case AArch64CC_HS:
	case AArch64CC_PL:
	case AArch64CC_LS:
	case AArch64CC_GE:
	case AArch64CC_LE:
	case AArch64CC_AL:
	case AArch64CC_NV:
		return true;
	default:
		return false;
	}
}

/// Return true if Code is an irreflexive relationship:
/// forall x. (CSET Code (CMP x x)) == 0
inline static bool AArch64CC_isIrreflexive(AArch64_CondCode Code)
{
	switch (Code) {
	case AArch64CC_NE:
	case AArch64CC_LO:
	case AArch64CC_MI:
	case AArch64CC_HI:
	case AArch64CC_LT:
	case AArch64CC_GT:
		return true;
	default:
		return false;
	}
}

// end namespace AArch64CC

struct SysAlias {
	const char *Name;
	arm64_sysreg sysreg;
	uint16_t Encoding;
	arm64_insn_group FeaturesRequired[3];
};

typedef struct SysAliasReg {
	const char *Name;
	arm64_sysreg sysreg;
	uint16_t Encoding;
	bool NeedsReg;
} SysAliasReg;

typedef struct SysAliasImm {
	const char *Name;
	arm64_sysreg sysreg;
	uint16_t Encoding;
	uint16_t ImmValue;
} SysAliasImm;

#define SVCR SysAlias

#define GET_SVCR_DECL
#include "AArch64GenSystemOperands.inc"

#define AT SysAlias

#define GET_AT_DECL
#include "AArch64GenSystemOperands.inc"

#define DB SysAlias

#define GET_DB_DECL
#include "AArch64GenSystemOperands.inc"

#define DBnXS SysAliasImm

#define GET_DBNXS_DECL
#include "AArch64GenSystemOperands.inc"

#define DC SysAlias

#define GET_DC_DECL
#include "AArch64GenSystemOperands.inc"

#define IC SysAliasReg

#define GET_IC_DECL
#include "AArch64GenSystemOperands.inc"

#define ISB SysAlias

#define GET_ISB_DECL
#include "AArch64GenSystemOperands.inc"

#define TSB SysAlias

#define GET_TSB_DECL
#include "AArch64GenSystemOperands.inc"

#define PRFM SysAlias

#define GET_PRFM_DECL
#include "AArch64GenSystemOperands.inc"

#define SVEPRFM SysAlias

#define GET_SVEPRFM_DECL
#include "AArch64GenSystemOperands.inc"

#define RPRFM SysAlias

#define GET_RPRFM_DECL
#include "AArch64GenSystemOperands.inc"

// namespace AArch64RPRFM

struct SVEPREDPAT {
	const char *Name;
	uint16_t Encoding;
};

#define GET_SVEPREDPAT_DECL
#include "AArch64GenSystemOperands.inc"

struct SVEVECLENSPECIFIER {
	const char *Name;
	uint16_t Encoding;
};

#define GET_SVEVECLENSPECIFIER_DECL
#include "AArch64GenSystemOperands.inc"

// namespace AArch64SVEVecLenSpecifier

struct ExactFPImm {
	const char *Name;
	int Enum;
	const char *Repr;
};

#define GET_EXACTFPIMM_DECL
#include "AArch64GenSystemOperands.inc"

#define PStateImm0_15 SysAlias

#define GET_PSTATEIMM0_15_DECL
#include "AArch64GenSystemOperands.inc"

#define PStateImm0_1 SysAlias

#define GET_PSTATEIMM0_1_DECL
#include "AArch64GenSystemOperands.inc"

#define PSB SysAlias

#define GET_PSB_DECL
#include "AArch64GenSystemOperands.inc"

#define BTI SysAlias

#define GET_BTI_DECL
#include "AArch64GenSystemOperands.inc"

enum ShiftExtSpecifiers {
	AArch64SE_Invalid = -1,
	AArch64SE_LSL,
	AArch64SE_MSL,
	AArch64SE_LSR,
	AArch64SE_ASR,
	AArch64SE_ROR,

	AArch64SE_UXTB,
	AArch64SE_UXTH,
	AArch64SE_UXTW,
	AArch64SE_UXTX,

	AArch64SE_SXTB,
	AArch64SE_SXTH,
	AArch64SE_SXTW,
	AArch64SE_SXTX
};

typedef enum VectorLayout {
	AArch64Layout_Invalid = -1,
	AArch64Layout_VL_8B,
	AArch64Layout_VL_4H,
	AArch64Layout_VL_2S,
	AArch64Layout_VL_1D,

	AArch64Layout_VL_16B,
	AArch64Layout_VL_8H,
	AArch64Layout_VL_4S,
	AArch64Layout_VL_2D,

	// Bare layout for the 128-bit vector
	// (only show ".b", ".h", ".s", ".d" without vector number)
	AArch64Layout_VL_B,
	AArch64Layout_VL_H,
	AArch64Layout_VL_S,
	AArch64Layout_VL_D
} AArch64Layout_VectorLayout;

typedef struct SysReg {
	const char *Name;
	const char *AltName;
	unsigned Encoding;
	bool Readable;
	bool Writeable;
	arm64_insn_group FeaturesRequired[3];
} AArch64SysReg;

#define GET_SYSREG_DECL
#include "AArch64GenSystemOperands.inc"

const AArch64SysReg *lookupSysRegByName(const char *Name);
const AArch64SysReg *lookupSysRegByEncoding(uint16_t Encoding);
const char *genericRegisterString(uint32_t Bits);

#define TLBI SysAliasReg

#define GET_TLBITable_DECL
#include "AArch64GenSystemOperands.inc"

#define PRCTX SysAliasReg

#define GET_PRCTX_DECL
#include "AArch64GenSystemOperands.inc"

/// Target Operand Flag enum.
enum TOF {
	//===------------------------------------------------------------------===//
	// AArch64 Specific MachineOperand flags.

	AArch64II_MO_NO_FLAG,

	AArch64II_MO_FRAGMENT = 0x7,

	/// MO_PAGE - A symbol operand with this flag represents the pc-relative
	/// offset of the 4K page containing the symbol.  This is used with the
	/// ADRP instruction.
	AArch64II_MO_PAGE = 1,

	/// MO_PAGEOFF - A symbol operand with this flag represents the offset of
	/// that symbol within a 4K page.  This offset is added to the page address
	/// to produce the complete address.
	AArch64II_MO_PAGEOFF = 2,

	/// MO_G3 - A symbol operand with this flag (granule 3) represents the high
	/// 16-bits of a 64-bit address, used in a MOVZ or MOVK instruction
	AArch64II_MO_G3 = 3,

	/// MO_G2 - A symbol operand with this flag (granule 2) represents the bits
	/// 32-47 of a 64-bit address, used in a MOVZ or MOVK instruction
	AArch64II_MO_G2 = 4,

	/// MO_G1 - A symbol operand with this flag (granule 1) represents the bits
	/// 16-31 of a 64-bit address, used in a MOVZ or MOVK instruction
	AArch64II_MO_G1 = 5,

	/// MO_G0 - A symbol operand with this flag (granule 0) represents the bits
	/// 0-15 of a 64-bit address, used in a MOVZ or MOVK instruction
	AArch64II_MO_G0 = 6,

	/// MO_HI12 - This flag indicates that a symbol operand represents the bits
	/// 13-24 of a 64-bit address, used in a arithmetic immediate-shifted-left-
	/// by-12-bits instruction.
	AArch64II_MO_HI12 = 7,

	/// MO_COFFSTUB - On a symbol operand "FOO", this indicates that the
	/// reference is actually to the ".refptr.FOO" symbol.  This is used for
	/// stub symbols on windows.
	AArch64II_MO_COFFSTUB = 0x8,

	/// MO_GOT - This flag indicates that a symbol operand represents the
	/// address of the GOT entry for the symbol, rather than the address of
	/// the symbol itself.
	AArch64II_MO_GOT = 0x10,

	/// MO_NC - Indicates whether the linker is expected to check the symbol
	/// reference for overflow. For example in an ADRP/ADD pair of relocations
	/// the ADRP usually does check, but not the ADD.
	AArch64II_MO_NC = 0x20,

	/// MO_TLS - Indicates that the operand being accessed is some kind of
	/// thread-local symbol. On Darwin, only one type of thread-local access
	/// exists (pre linker-relaxation), but on ELF the TLSModel used for the
	/// referee will affect interpretation.
	AArch64II_MO_TLS = 0x40,

	/// MO_DLLIMPORT - On a symbol operand, this represents that the reference
	/// to the symbol is for an import stub.  This is used for DLL import
	/// storage class indication on Windows.
	AArch64II_MO_DLLIMPORT = 0x80,

	/// MO_S - Indicates that the bits of the symbol operand represented by
	/// MO_G0 etc are signed.
	AArch64II_MO_S = 0x100,

	/// MO_PREL - Indicates that the bits of the symbol operand represented by
	/// MO_G0 etc are PC relative.
	AArch64II_MO_PREL = 0x200,

	/// MO_TAGGED - With MO_PAGE, indicates that the page includes a memory tag
	/// in bits 56-63.
	/// On a FrameIndex operand, indicates that the underlying memory is tagged
	/// with an unknown tag value (MTE); this needs to be lowered either to an
	/// SP-relative load or store instruction (which do not check tags), or to
	/// an LDG instruction to obtain the tag value.
	AArch64II_MO_TAGGED = 0x400,

	/// MO_DLLIMPORTAUX - Symbol refers to "auxilliary" import stub. On
	/// Arm64EC, there are two kinds of import stubs used for DLL import of
	/// functions: MO_DLLIMPORT refers to natively callable Arm64 code, and
	/// MO_DLLIMPORTAUX refers to the original address which can be compared
	/// for equality.
	AArch64II_MO_DLLIMPORTAUX = 0x800,
};

// end namespace AArch64II

//===----------------------------------------------------------------------===//
// v8.3a Pointer Authentication
//

typedef enum ID {
	AArch64PACKey_IA = 0,
	AArch64PACKey_IB = 1,
	AArch64PACKey_DA = 2,
	AArch64PACKey_DB = 3,
	AArch64PACKey_LAST = AArch64PACKey_DB
} AArch64PACKey_ID;

// namespace AArch64PACKey

/// Return 2-letter identifier string for numeric key ID.
inline static const char *AArch64PACKeyIDToString(AArch64PACKey_ID KeyID)
{
	switch (KeyID) {
	case AArch64PACKey_IA:
		return "ia";
	case AArch64PACKey_IB:
		return "ib";
	case AArch64PACKey_DA:
		return "da";
	case AArch64PACKey_DB:
		return "db";
	}
}

/// Return numeric key ID for 2-letter identifier string.
inline static AArch64PACKey_ID
AArch64StringToPACKeyID(const char *Name)
{
	if (strcmp(Name, "ia") == 0)
		return AArch64PACKey_IA;
	if (strcmp(Name, "ib") == 0)
		return AArch64PACKey_IB;
	if (strcmp(Name, "da") == 0)
		return AArch64PACKey_DA;
	if (strcmp(Name, "db") == 0)
		return AArch64PACKey_DB;
	assert(0 && "Invalid PAC key");
}

// The number of bits in a SVE register is architecturally defined
// to be a multiple of this value.  If <M x t> has this number of bits,
// a <n x M x t> vector can be stored in a SVE register without any
// redundant bits.  If <M x t> has this number of bits divided by P,
// a <n x M x t> vector is stored in a SVE register by placing index i
// in index i*P of a <n x (M*P) x t> vector.  The other elements of the
// <n x (M*P) x t> vector (such as index 1) are undefined.
static unsigned SVEBitsPerBlock = 128;
static unsigned SVEMaxBitsPerVector = 2048;
// end namespace AArch64
// end namespace llvm

#endif
