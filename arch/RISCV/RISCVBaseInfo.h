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

//===-- RISCVBaseInfo.h - Top level definitions for RISC-V MC ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone enum definitions for the RISC-V target
// useful for the compiler back-end and the MC libraries.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVBASEINFO_H
#define LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVBASEINFO_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../utils.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

// RISCVII - This namespace holds all of the target specific flags that
// instruction info tracks. All definitions must match RISCVInstrFormats.td.
// CS namespace begin: RISCVII

// RISC-V Specific Machine Operand Flags
enum {
	RISCVII_MO_None = 0,
	RISCVII_MO_CALL = 1,
	RISCVII_MO_LO = 3,
	RISCVII_MO_HI = 4,
	RISCVII_MO_PCREL_LO = 5,
	RISCVII_MO_PCREL_HI = 6,
	RISCVII_MO_GOT_HI = 7,
	RISCVII_MO_TPREL_LO = 8,
	RISCVII_MO_TPREL_HI = 9,
	RISCVII_MO_TPREL_ADD = 10,
	RISCVII_MO_TLS_GOT_HI = 11,
	RISCVII_MO_TLS_GD_HI = 12,
	RISCVII_MO_TLSDESC_HI = 13,
	RISCVII_MO_TLSDESC_LOAD_LO = 14,
	RISCVII_MO_TLSDESC_ADD_LO = 15,
	RISCVII_MO_TLSDESC_CALL = 16,

	// Used to differentiate between target-specific "direct" flags and "bitmask"
	// flags. A machine operand can only have one "direct" flag, but can have
	// multiple "bitmask" flags.
	RISCVII_MO_DIRECT_FLAG_MASK = 31
};

typedef enum OperandType {
	RISCVOp_OPERAND_FIRST_RISCV_IMM = MCOI_OPERAND_FIRST_TARGET,
	RISCVOp_OPERAND_UIMM1 = RISCVOp_OPERAND_FIRST_RISCV_IMM,
	RISCVOp_OPERAND_UIMM2,
	RISCVOp_OPERAND_UIMM2_LSB0,
	RISCVOp_OPERAND_UIMM3,
	RISCVOp_OPERAND_UIMM4,
	RISCVOp_OPERAND_UIMM5,
	RISCVOp_OPERAND_UIMM6,
	RISCVOp_OPERAND_UIMM7,
	RISCVOp_OPERAND_UIMM7_LSB00,
	RISCVOp_OPERAND_UIMM8_LSB00,
	RISCVOp_OPERAND_UIMM8,
	RISCVOp_OPERAND_UIMM8_LSB000,
	RISCVOp_OPERAND_UIMM8_GE32,
	RISCVOp_OPERAND_UIMM9_LSB000,
	RISCVOp_OPERAND_UIMM10_LSB00_NONZERO,
	RISCVOp_OPERAND_UIMM12,
	RISCVOp_OPERAND_ZERO,
	RISCVOp_OPERAND_SIMM5,
	RISCVOp_OPERAND_SIMM5_PLUS1,
	RISCVOp_OPERAND_SIMM6,
	RISCVOp_OPERAND_SIMM6_NONZERO,
	RISCVOp_OPERAND_SIMM10_LSB0000_NONZERO,
	RISCVOp_OPERAND_SIMM12,
	RISCVOp_OPERAND_SIMM12_LSB00000,
	RISCVOp_OPERAND_UIMM20,
	RISCVOp_OPERAND_UIMMLOG2XLEN,
	RISCVOp_OPERAND_UIMMLOG2XLEN_NONZERO,
	RISCVOp_OPERAND_CLUI_IMM,
	RISCVOp_OPERAND_VTYPEI10,
	RISCVOp_OPERAND_VTYPEI11,
	RISCVOp_OPERAND_RVKRNUM,
	RISCVOp_OPERAND_RVKRNUM_0_7,
	RISCVOp_OPERAND_RVKRNUM_1_10,
	RISCVOp_OPERAND_RVKRNUM_2_14,
	OPERAND_LAST_RISCV_IMM = RISCVOp_OPERAND_RVKRNUM_2_14,
	// Operand is either a register or uimm5, this is used by V extension pseudo
	// instructions to represent a value that be passed as AVL to either vsetvli
	// or vsetivli.
	RISCVOp_OPERAND_AVL,
} RISCVOp_OperandType;

// Describes the predecessor/successor bits used in the FENCE instruction.

typedef enum FenceField {
	RISCVFenceField_I = 8,
	RISCVFenceField_O = 4,
	RISCVFenceField_R = 2,
	RISCVFenceField_W = 1
} RISCVFenceField_FenceField;

// Describes the supported floating point rounding mode encodings.

typedef enum RoundingMode {
	RISCVFPRndMode_RNE = 0,
	RISCVFPRndMode_RTZ = 1,
	RISCVFPRndMode_RDN = 2,
	RISCVFPRndMode_RUP = 3,
	RISCVFPRndMode_RMM = 4,
	RISCVFPRndMode_DYN = 7,
	RISCVFPRndMode_Invalid
} RISCVFPRndMode_RoundingMode;

inline static bool RISCVFPRndMode_isValidRoundingMode(unsigned Mode)
{
	switch (Mode) {
	default:
		return false;
	case RISCVFPRndMode_RNE:
	case RISCVFPRndMode_RTZ:
	case RISCVFPRndMode_RDN:
	case RISCVFPRndMode_RUP:
	case RISCVFPRndMode_RMM:
	case RISCVFPRndMode_DYN:
		return true;
	}
}

inline static const char *RISCVFPRndMode_roundingModeToString(unsigned RndMode)
{
	switch (RndMode) {
	default:
		CS_ASSERT(0 && "Unknown floating point rounding mode");
	case RISCVFPRndMode_RNE:
		return "rne";
	case RISCVFPRndMode_RTZ:
		return "rtz";
	case RISCVFPRndMode_RDN:
		return "rdn";
	case RISCVFPRndMode_RUP:
		return "rup";
	case RISCVFPRndMode_RMM:
		return "rmm";
	case RISCVFPRndMode_DYN:
		return "dyn";
	}
}

inline static bool RISCVVType_isTailAgnostic(unsigned VType)
{
	return VType & 0x40;
}

inline static bool RISCVVType_isMaskAgnostic(unsigned VType)
{
	return VType & 0x80;
}

typedef enum RLISTENCODE {
	RISCVZC_RLISTENCODE_RA = 4,
	RISCVZC_RLISTENCODE_RA_S0,
	RISCVZC_RLISTENCODE_RA_S0_S1,
	RISCVZC_RLISTENCODE_RA_S0_S2,
	RISCVZC_RLISTENCODE_RA_S0_S3,
	RISCVZC_RLISTENCODE_RA_S0_S4,
	RISCVZC_RLISTENCODE_RA_S0_S5,
	RISCVZC_RLISTENCODE_RA_S0_S6,
	RISCVZC_RLISTENCODE_RA_S0_S7,
	RISCVZC_RLISTENCODE_RA_S0_S8,
	RISCVZC_RLISTENCODE_RA_S0_S9,
	// note - to include s10, s11 must also be included
	RISCVZC_RLISTENCODE_RA_S0_S11,
	RISCVZC_RLISTENCODE_INVALID_RLIST,
} RISCVZC_RLISTENCODE;

inline static unsigned RISCVZC_getStackAdjBase(unsigned RlistVal, bool IsRV64,
					       bool IsEABI)
{
	CS_ASSERT(RlistVal != RISCVZC_RLISTENCODE_INVALID_RLIST &&
		  "{ra, s0-s10} is not supported, s11 must be included.");
	if (IsEABI)
		return 16;
	if (!IsRV64) {
		switch (RlistVal) {
		case RISCVZC_RLISTENCODE_RA:
		case RISCVZC_RLISTENCODE_RA_S0:
		case RISCVZC_RLISTENCODE_RA_S0_S1:
		case RISCVZC_RLISTENCODE_RA_S0_S2:
			return 16;
		case RISCVZC_RLISTENCODE_RA_S0_S3:
		case RISCVZC_RLISTENCODE_RA_S0_S4:
		case RISCVZC_RLISTENCODE_RA_S0_S5:
		case RISCVZC_RLISTENCODE_RA_S0_S6:
			return 32;
		case RISCVZC_RLISTENCODE_RA_S0_S7:
		case RISCVZC_RLISTENCODE_RA_S0_S8:
		case RISCVZC_RLISTENCODE_RA_S0_S9:
			return 48;
		case RISCVZC_RLISTENCODE_RA_S0_S11:
			return 64;
		}
	} else {
		switch (RlistVal) {
		case RISCVZC_RLISTENCODE_RA:
		case RISCVZC_RLISTENCODE_RA_S0:
			return 16;
		case RISCVZC_RLISTENCODE_RA_S0_S1:
		case RISCVZC_RLISTENCODE_RA_S0_S2:
			return 32;
		case RISCVZC_RLISTENCODE_RA_S0_S3:
		case RISCVZC_RLISTENCODE_RA_S0_S4:
			return 48;
		case RISCVZC_RLISTENCODE_RA_S0_S5:
		case RISCVZC_RLISTENCODE_RA_S0_S6:
			return 64;
		case RISCVZC_RLISTENCODE_RA_S0_S7:
		case RISCVZC_RLISTENCODE_RA_S0_S8:
			return 80;
		case RISCVZC_RLISTENCODE_RA_S0_S9:
			return 96;
		case RISCVZC_RLISTENCODE_RA_S0_S11:
			return 112;
		}
	}
	CS_ASSERT(0 && "Unexpected RlistVal");
	return 0; // unreachable
}

typedef enum VLMUL {
	RISCVII_LMUL_1 = 0,
	RISCVII_LMUL_2,
	RISCVII_LMUL_4,
	RISCVII_LMUL_8,
	RISCVII_LMUL_RESERVED,
	RISCVII_LMUL_F8,
	RISCVII_LMUL_F4,
	RISCVII_LMUL_F2
} RISCVII_VLMUL;

inline static RISCVII_VLMUL RISCVVType_getVLMUL(unsigned VType)
{
	unsigned VLMUL = VType & 0x7;
	return (RISCVII_VLMUL)(VLMUL);
}

inline static unsigned RISCVVType_decodeVSEW(unsigned VSEW)
{
	CS_ASSERT(VSEW < 8 && "Unexpected VSEW value");
	return 1 << (VSEW + 3);
}

inline static unsigned RISCVVType_getSEW(unsigned VType)
{
	unsigned VSEW = (VType >> 3) & 0x7;
	return RISCVVType_decodeVSEW(VSEW);
}

typedef struct {
	unsigned raw_val;
} RegVal;

typedef struct SysReg {
	const char *Name;
	RegVal val1;
	const char *AltName;
	RegVal val2;
	const char *DeprecatedName;
	unsigned Encoding;
	unsigned DummyFeatureArray[1];
	bool isRV32Only;
} RISCV_SysReg;

void printVType(unsigned VType, SStream *OS);

float getFPImm(unsigned Imm);

void RISCVZC_printSpimm(int64_t Spimm, SStream *OS);

#endif
