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

#include "../../utils.h"
#include "capstone/aarch64.h"

#define GET_SUBTARGETINFO_ENUM
#include "AArch64GenSubtargetInfo.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "AArch64GenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

static inline unsigned getWRegFromXReg(unsigned Reg)
{
	switch (Reg) {
	case AArch64_X0:
		return AArch64_W0;
	case AArch64_X1:
		return AArch64_W1;
	case AArch64_X2:
		return AArch64_W2;
	case AArch64_X3:
		return AArch64_W3;
	case AArch64_X4:
		return AArch64_W4;
	case AArch64_X5:
		return AArch64_W5;
	case AArch64_X6:
		return AArch64_W6;
	case AArch64_X7:
		return AArch64_W7;
	case AArch64_X8:
		return AArch64_W8;
	case AArch64_X9:
		return AArch64_W9;
	case AArch64_X10:
		return AArch64_W10;
	case AArch64_X11:
		return AArch64_W11;
	case AArch64_X12:
		return AArch64_W12;
	case AArch64_X13:
		return AArch64_W13;
	case AArch64_X14:
		return AArch64_W14;
	case AArch64_X15:
		return AArch64_W15;
	case AArch64_X16:
		return AArch64_W16;
	case AArch64_X17:
		return AArch64_W17;
	case AArch64_X18:
		return AArch64_W18;
	case AArch64_X19:
		return AArch64_W19;
	case AArch64_X20:
		return AArch64_W20;
	case AArch64_X21:
		return AArch64_W21;
	case AArch64_X22:
		return AArch64_W22;
	case AArch64_X23:
		return AArch64_W23;
	case AArch64_X24:
		return AArch64_W24;
	case AArch64_X25:
		return AArch64_W25;
	case AArch64_X26:
		return AArch64_W26;
	case AArch64_X27:
		return AArch64_W27;
	case AArch64_X28:
		return AArch64_W28;
	case AArch64_FP:
		return AArch64_W29;
	case AArch64_LR:
		return AArch64_W30;
	case AArch64_SP:
		return AArch64_WSP;
	case AArch64_XZR:
		return AArch64_WZR;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline unsigned getXRegFromWReg(unsigned Reg)
{
	switch (Reg) {
	case AArch64_W0:
		return AArch64_X0;
	case AArch64_W1:
		return AArch64_X1;
	case AArch64_W2:
		return AArch64_X2;
	case AArch64_W3:
		return AArch64_X3;
	case AArch64_W4:
		return AArch64_X4;
	case AArch64_W5:
		return AArch64_X5;
	case AArch64_W6:
		return AArch64_X6;
	case AArch64_W7:
		return AArch64_X7;
	case AArch64_W8:
		return AArch64_X8;
	case AArch64_W9:
		return AArch64_X9;
	case AArch64_W10:
		return AArch64_X10;
	case AArch64_W11:
		return AArch64_X11;
	case AArch64_W12:
		return AArch64_X12;
	case AArch64_W13:
		return AArch64_X13;
	case AArch64_W14:
		return AArch64_X14;
	case AArch64_W15:
		return AArch64_X15;
	case AArch64_W16:
		return AArch64_X16;
	case AArch64_W17:
		return AArch64_X17;
	case AArch64_W18:
		return AArch64_X18;
	case AArch64_W19:
		return AArch64_X19;
	case AArch64_W20:
		return AArch64_X20;
	case AArch64_W21:
		return AArch64_X21;
	case AArch64_W22:
		return AArch64_X22;
	case AArch64_W23:
		return AArch64_X23;
	case AArch64_W24:
		return AArch64_X24;
	case AArch64_W25:
		return AArch64_X25;
	case AArch64_W26:
		return AArch64_X26;
	case AArch64_W27:
		return AArch64_X27;
	case AArch64_W28:
		return AArch64_X28;
	case AArch64_W29:
		return AArch64_FP;
	case AArch64_W30:
		return AArch64_LR;
	case AArch64_WSP:
		return AArch64_SP;
	case AArch64_WZR:
		return AArch64_XZR;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline unsigned getXRegFromXRegTuple(unsigned RegTuple)
{
	switch (RegTuple) {
	case AArch64_X0_X1_X2_X3_X4_X5_X6_X7:
		return AArch64_X0;
	case AArch64_X2_X3_X4_X5_X6_X7_X8_X9:
		return AArch64_X2;
	case AArch64_X4_X5_X6_X7_X8_X9_X10_X11:
		return AArch64_X4;
	case AArch64_X6_X7_X8_X9_X10_X11_X12_X13:
		return AArch64_X6;
	case AArch64_X8_X9_X10_X11_X12_X13_X14_X15:
		return AArch64_X8;
	case AArch64_X10_X11_X12_X13_X14_X15_X16_X17:
		return AArch64_X10;
	case AArch64_X12_X13_X14_X15_X16_X17_X18_X19:
		return AArch64_X12;
	case AArch64_X14_X15_X16_X17_X18_X19_X20_X21:
		return AArch64_X14;
	case AArch64_X16_X17_X18_X19_X20_X21_X22_X23:
		return AArch64_X16;
	case AArch64_X18_X19_X20_X21_X22_X23_X24_X25:
		return AArch64_X18;
	case AArch64_X20_X21_X22_X23_X24_X25_X26_X27:
		return AArch64_X20;
	case AArch64_X22_X23_X24_X25_X26_X27_X28_FP:
		return AArch64_X22;
	}
	// For anything else, return it unchanged.
	return RegTuple;
}

static inline unsigned getBRegFromDReg(unsigned Reg)
{
	switch (Reg) {
	case AArch64_D0:
		return AArch64_B0;
	case AArch64_D1:
		return AArch64_B1;
	case AArch64_D2:
		return AArch64_B2;
	case AArch64_D3:
		return AArch64_B3;
	case AArch64_D4:
		return AArch64_B4;
	case AArch64_D5:
		return AArch64_B5;
	case AArch64_D6:
		return AArch64_B6;
	case AArch64_D7:
		return AArch64_B7;
	case AArch64_D8:
		return AArch64_B8;
	case AArch64_D9:
		return AArch64_B9;
	case AArch64_D10:
		return AArch64_B10;
	case AArch64_D11:
		return AArch64_B11;
	case AArch64_D12:
		return AArch64_B12;
	case AArch64_D13:
		return AArch64_B13;
	case AArch64_D14:
		return AArch64_B14;
	case AArch64_D15:
		return AArch64_B15;
	case AArch64_D16:
		return AArch64_B16;
	case AArch64_D17:
		return AArch64_B17;
	case AArch64_D18:
		return AArch64_B18;
	case AArch64_D19:
		return AArch64_B19;
	case AArch64_D20:
		return AArch64_B20;
	case AArch64_D21:
		return AArch64_B21;
	case AArch64_D22:
		return AArch64_B22;
	case AArch64_D23:
		return AArch64_B23;
	case AArch64_D24:
		return AArch64_B24;
	case AArch64_D25:
		return AArch64_B25;
	case AArch64_D26:
		return AArch64_B26;
	case AArch64_D27:
		return AArch64_B27;
	case AArch64_D28:
		return AArch64_B28;
	case AArch64_D29:
		return AArch64_B29;
	case AArch64_D30:
		return AArch64_B30;
	case AArch64_D31:
		return AArch64_B31;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline unsigned getDRegFromBReg(unsigned Reg)
{
	switch (Reg) {
	case AArch64_B0:
		return AArch64_D0;
	case AArch64_B1:
		return AArch64_D1;
	case AArch64_B2:
		return AArch64_D2;
	case AArch64_B3:
		return AArch64_D3;
	case AArch64_B4:
		return AArch64_D4;
	case AArch64_B5:
		return AArch64_D5;
	case AArch64_B6:
		return AArch64_D6;
	case AArch64_B7:
		return AArch64_D7;
	case AArch64_B8:
		return AArch64_D8;
	case AArch64_B9:
		return AArch64_D9;
	case AArch64_B10:
		return AArch64_D10;
	case AArch64_B11:
		return AArch64_D11;
	case AArch64_B12:
		return AArch64_D12;
	case AArch64_B13:
		return AArch64_D13;
	case AArch64_B14:
		return AArch64_D14;
	case AArch64_B15:
		return AArch64_D15;
	case AArch64_B16:
		return AArch64_D16;
	case AArch64_B17:
		return AArch64_D17;
	case AArch64_B18:
		return AArch64_D18;
	case AArch64_B19:
		return AArch64_D19;
	case AArch64_B20:
		return AArch64_D20;
	case AArch64_B21:
		return AArch64_D21;
	case AArch64_B22:
		return AArch64_D22;
	case AArch64_B23:
		return AArch64_D23;
	case AArch64_B24:
		return AArch64_D24;
	case AArch64_B25:
		return AArch64_D25;
	case AArch64_B26:
		return AArch64_D26;
	case AArch64_B27:
		return AArch64_D27;
	case AArch64_B28:
		return AArch64_D28;
	case AArch64_B29:
		return AArch64_D29;
	case AArch64_B30:
		return AArch64_D30;
	case AArch64_B31:
		return AArch64_D31;
	}
	// For anything else, return it unchanged.
	return Reg;
}

static inline bool atomicBarrierDroppedOnZero(unsigned Opcode)
{
	switch (Opcode) {
	case AArch64_LDADDAB:
	case AArch64_LDADDAH:
	case AArch64_LDADDAW:
	case AArch64_LDADDAX:
	case AArch64_LDADDALB:
	case AArch64_LDADDALH:
	case AArch64_LDADDALW:
	case AArch64_LDADDALX:
	case AArch64_LDCLRAB:
	case AArch64_LDCLRAH:
	case AArch64_LDCLRAW:
	case AArch64_LDCLRAX:
	case AArch64_LDCLRALB:
	case AArch64_LDCLRALH:
	case AArch64_LDCLRALW:
	case AArch64_LDCLRALX:
	case AArch64_LDEORAB:
	case AArch64_LDEORAH:
	case AArch64_LDEORAW:
	case AArch64_LDEORAX:
	case AArch64_LDEORALB:
	case AArch64_LDEORALH:
	case AArch64_LDEORALW:
	case AArch64_LDEORALX:
	case AArch64_LDSETAB:
	case AArch64_LDSETAH:
	case AArch64_LDSETAW:
	case AArch64_LDSETAX:
	case AArch64_LDSETALB:
	case AArch64_LDSETALH:
	case AArch64_LDSETALW:
	case AArch64_LDSETALX:
	case AArch64_LDSMAXAB:
	case AArch64_LDSMAXAH:
	case AArch64_LDSMAXAW:
	case AArch64_LDSMAXAX:
	case AArch64_LDSMAXALB:
	case AArch64_LDSMAXALH:
	case AArch64_LDSMAXALW:
	case AArch64_LDSMAXALX:
	case AArch64_LDSMINAB:
	case AArch64_LDSMINAH:
	case AArch64_LDSMINAW:
	case AArch64_LDSMINAX:
	case AArch64_LDSMINALB:
	case AArch64_LDSMINALH:
	case AArch64_LDSMINALW:
	case AArch64_LDSMINALX:
	case AArch64_LDUMAXAB:
	case AArch64_LDUMAXAH:
	case AArch64_LDUMAXAW:
	case AArch64_LDUMAXAX:
	case AArch64_LDUMAXALB:
	case AArch64_LDUMAXALH:
	case AArch64_LDUMAXALW:
	case AArch64_LDUMAXALX:
	case AArch64_LDUMINAB:
	case AArch64_LDUMINAH:
	case AArch64_LDUMINAW:
	case AArch64_LDUMINAX:
	case AArch64_LDUMINALB:
	case AArch64_LDUMINALH:
	case AArch64_LDUMINALW:
	case AArch64_LDUMINALX:
	case AArch64_SWPAB:
	case AArch64_SWPAH:
	case AArch64_SWPAW:
	case AArch64_SWPAX:
	case AArch64_SWPALB:
	case AArch64_SWPALH:
	case AArch64_SWPALW:
	case AArch64_SWPALX:
		return true;
	}
	return false;
}

// MOVE-NOTICE: AArch64CC_CondCode : moved to aarch64.h
// MOVE-NOTICE: AArch64CC_getCondCodeName : moved to aarch64.h
// MOVE-NOTICE: AArch64CC_getInvertedCondCode : moved to aarch64.h
// MOVE-NOTICE: AArch64CC_getNZCVToSatisfyCondCode : moved to aarch64.h

typedef struct SysAlias {
	const char *Name;
	aarch64_sysop_alias SysAlias;
	uint16_t Encoding;
	aarch64_insn_group FeaturesRequired[3];
} SysAlias;

typedef struct SysAliasReg {
	const char *Name;
	aarch64_sysop_reg SysReg;
	uint16_t Encoding;
	bool NeedsReg;
	aarch64_insn_group FeaturesRequired[3];
} SysAliasReg;

typedef struct SysAliasImm {
	const char *Name;
	aarch64_sysop_imm SysImm;
	uint16_t ImmValue;
	uint16_t Encoding;
	aarch64_insn_group FeaturesRequired[3];
} SysAliasImm;

// CS namespace begin: AArch64SVCR

#define AArch64SVCR_SVCR SysAlias

#define GET_SVCR_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64SVCR

// CS namespace begin: AArch64AT

#define AArch64AT_AT SysAlias

#define GET_AT_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64AT

// CS namespace begin: AArch64DB

#define AArch64DB_DB SysAlias

#define GET_DB_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64DB

// CS namespace begin: AArch64DBnXS

#define AArch64DBnXS_DBnXS SysAliasImm

#define GET_DBNXS_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64DBnXS

// CS namespace begin: AArch64DC

#define AArch64DC_DC SysAlias

#define GET_DC_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64DC

// CS namespace begin: AArch64IC

#define AArch64IC_IC SysAliasReg

#define GET_IC_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64IC

// CS namespace begin: AArch64ISB

#define AArch64ISB_ISB SysAlias

#define GET_ISB_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64ISB

// CS namespace begin: AArch64TSB

#define AArch64TSB_TSB SysAlias

#define GET_TSB_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64TSB

// CS namespace begin: AArch64PRFM

#define AArch64PRFM_PRFM SysAlias

#define GET_PRFM_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64PRFM

// CS namespace begin: AArch64SVEPRFM

#define AArch64SVEPRFM_SVEPRFM SysAlias

#define GET_SVEPRFM_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64SVEPRFM

// CS namespace begin: AArch64RPRFM

#define AArch64RPRFM_RPRFM SysAlias

#define GET_RPRFM_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64RPRFM

// CS namespace begin: AArch64SVEPredPattern

typedef struct SVEPREDPAT {
	const char *Name;
	aarch64_sysop_alias SysAlias;
	uint16_t Encoding;
} AArch64SVEPredPattern_SVEPREDPAT;

#define GET_SVEPREDPAT_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64SVEPredPattern

// CS namespace begin: AArch64SVEVecLenSpecifier

typedef struct SVEVECLENSPECIFIER {
	const char *Name;
	aarch64_sysop_alias SysAlias;
	uint16_t Encoding;
} AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER;

#define GET_SVEVECLENSPECIFIER_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64SVEVecLenSpecifier

// namespace AArch64SVEVecLenSpecifier

/// Return the number of active elements for VL1 to VL256 predicate pattern,
/// zero for all other patterns.
static inline unsigned getNumElementsFromSVEPredPattern(unsigned Pattern)
{
	switch (Pattern) {
	default:
		return 0;
	case AARCH64_SVEPREDPAT_VL1:
	case AARCH64_SVEPREDPAT_VL2:
	case AARCH64_SVEPREDPAT_VL3:
	case AARCH64_SVEPREDPAT_VL4:
	case AARCH64_SVEPREDPAT_VL5:
	case AARCH64_SVEPREDPAT_VL6:
	case AARCH64_SVEPREDPAT_VL7:
	case AARCH64_SVEPREDPAT_VL8:
		return Pattern;
	case AARCH64_SVEPREDPAT_VL16:
		return 16;
	case AARCH64_SVEPREDPAT_VL32:
		return 32;
	case AARCH64_SVEPREDPAT_VL64:
		return 64;
	case AARCH64_SVEPREDPAT_VL128:
		return 128;
	case AARCH64_SVEPREDPAT_VL256:
		return 256;
	}
}

/// Return specific VL predicate pattern based on the number of elements.
static inline unsigned getSVEPredPatternFromNumElements(unsigned MinNumElts)
{
	switch (MinNumElts) {
	default:
		return 0;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
		return MinNumElts;
	case 16:
		return AARCH64_SVEPREDPAT_VL16;
	case 32:
		return AARCH64_SVEPREDPAT_VL32;
	case 64:
		return AARCH64_SVEPREDPAT_VL64;
	case 128:
		return AARCH64_SVEPREDPAT_VL128;
	case 256:
		return AARCH64_SVEPREDPAT_VL256;
	}
}

// CS namespace begin: AArch64ExactFPImm

typedef struct ExactFPImm {
	const char *Name;
	aarch64_sysop_imm SysImm;
	int Enum;
	const char *Repr;
} AArch64ExactFPImm_ExactFPImm;

enum {
	AArch64ExactFPImm_half = 1,
	AArch64ExactFPImm_one = 2,
	AArch64ExactFPImm_two = 3,
	AArch64ExactFPImm_zero = 0,
};

#define GET_EXACTFPIMM_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64ExactFPImm

// CS namespace begin: AArch64PState

#define AArch64PState_PStateImm0_15 SysAlias

#define GET_PSTATEIMM0_15_DECL

#include "AArch64GenSystemOperands.inc"

#define AArch64PState_PStateImm0_1 SysAlias

#define GET_PSTATEIMM0_1_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64PState

// CS namespace begin: AArch64PSBHint

#define AArch64PSBHint_PSB SysAlias

#define GET_PSB_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64PSBHint

// CS namespace begin: AArch64BTIHint

#define AArch64BTIHint_BTI SysAlias

#define GET_BTI_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64BTIHint

// CS namespace begin: AArch64SE

typedef enum ShiftExtSpecifiers {
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
} AArch64SE_ShiftExtSpecifiers;

// CS namespace end: AArch64SE

// CS namespace begin: AArch64Layout

// MOVE_NOTICE: AArch64Layout_VectorLayout - move to aarch64.h
// MOVE_NOTICE: AArch64VectorLayoutToString - move to aarch64.h
// MOVE_NOTICE: AArch64StringToVectorLayout - move to aarch64.h

// CS namespace end: AArch64Layout

// CS namespace begin: AArch64SysReg

typedef struct SysReg {
	const char *Name;
	aarch64_sysop_reg SysReg;
	const char *AltName;
	aarch64_sysop_reg AliasReg;
	unsigned Encoding;
	bool Readable;
	bool Writeable;
	aarch64_insn_group FeaturesRequired[3];
} AArch64SysReg_SysReg;

#define GET_SYSREG_DECL

#include "AArch64GenSystemOperands.inc"

const AArch64SysReg_SysReg *AArch64SysReg_lookupSysRegByName(const char *Name);
const AArch64SysReg_SysReg *
AArch64SysReg_lookupSysRegByEncoding(uint16_t Encoding);
#define AARCH64_GRS_LEN 128
void AArch64SysReg_genericRegisterString(uint32_t Bits, char *result);

// CS namespace end: AArch64SysReg

// CS namespace begin: AArch64TLBI

#define AArch64TLBI_TLBI SysAliasReg

#define GET_TLBITable_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64TLBI

// CS namespace begin: AArch64PRCTX

#define AArch64PRCTX_PRCTX SysAliasReg

#define GET_PRCTX_DECL

#include "AArch64GenSystemOperands.inc"

// CS namespace end: AArch64PRCTX

// CS namespace begin: AArch64II

/// Target Operand Flag enum.
typedef enum TOF {
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

	/// MO_ARM64EC_CALLMANGLE - Operand refers to the Arm64EC-mangled version
	/// of a symbol, not the original. For dllimport symbols, this means it
	/// uses "__imp_aux".  For other symbols, this means it uses the mangled
	/// ("#" prefix for C) name.
	AArch64II_MO_ARM64EC_CALLMANGLE = 0x800,
} AArch64II_TOF;

// CS namespace end: AArch64II

// end namespace AArch64II

//===----------------------------------------------------------------------===//
// v8.3a Pointer Authentication
//

// CS namespace begin: AArch64PACKey

typedef enum ID {
	AArch64PACKey_IA = 0,
	AArch64PACKey_IB = 1,
	AArch64PACKey_DA = 2,
	AArch64PACKey_DB = 3,
	AArch64PACKey_LAST = AArch64PACKey_DB,
	AArch64PACKey_INVALID,
} AArch64PACKey_ID;

// CS namespace end: AArch64PACKey

// namespace AArch64PACKey

/// Return 2-letter identifier string for numeric key ID.
static inline const char *AArch64PACKeyIDToString(AArch64PACKey_ID KeyID)
{
	switch (KeyID) {
	default:
		break;
	case AArch64PACKey_IA:
		return "ia";
	case AArch64PACKey_IB:
		return "ib";
	case AArch64PACKey_DA:
		return "da";
	case AArch64PACKey_DB:
		return "db";
	}
	return NULL;
}

/// Return numeric key ID for 2-letter identifier string.
static inline AArch64PACKey_ID AArch64StringToPACKeyID(const char *Name)
{
	if (strcmp(Name, "ia") == 0)
		return AArch64PACKey_IA;
	if (strcmp(Name, "ib") == 0)
		return AArch64PACKey_IB;
	if (strcmp(Name, "da") == 0)
		return AArch64PACKey_DA;
	if (strcmp(Name, "db") == 0)
		return AArch64PACKey_DB;
	CS_ASSERT_RET_VAL(0 && "Invalid PAC key", AArch64PACKey_INVALID);
	return AArch64PACKey_LAST;
}

// CS namespace begin: AArch64

// The number of bits in a SVE register is architecturally defined
// to be a multiple of this value.  If <M x t> has this number of bits,
// a <n x M x t> vector can be stored in a SVE register without any
// redundant bits.  If <M x t> has this number of bits divided by P,
// a <n x M x t> vector is stored in a SVE register by placing index i
// in index i*P of a <n x (M*P) x t> vector.  The other elements of the
// <n x (M*P) x t> vector (such as index 1) are undefined.
static const unsigned SVEBitsPerBlock = 128;

static const unsigned SVEMaxBitsPerVector = 2048;

// CS namespace end: AArch64

// end namespace AArch64
// end namespace llvm

#endif
