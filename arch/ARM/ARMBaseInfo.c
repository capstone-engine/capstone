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

//===-- ARMBaseInfo.cpp - ARM Base encoding information------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides basic encoding and assembly information for ARM.
//
//===----------------------------------------------------------------------===//

#include <capstone/platform.h>

#include "ARMBaseInfo.h"
#include "../../utils.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

// CS namespace begin: ARMSysReg

// lookup system register using 12-bit SYSm value.
// Note: the search is uniqued using M1 mask
const char *get_pred_mask(ARM_PredBlockMask pred_mask)
{
	switch (pred_mask) {
	default:
		CS_ASSERT_RET_VAL(0 && "pred_mask not handled.", NULL);
	case ARM_T:
		return "T";
	case ARM_TT:
		return "TT";
	case ARM_TE:
		return "TE";
	case ARM_TTT:
		return "TTT";
	case ARM_TTE:
		return "TTE";
	case ARM_TEE:
		return "TEE";
	case ARM_TET:
		return "TET";
	case ARM_TTTT:
		return "TTTT";
	case ARM_TTTE:
		return "TTTE";
	case ARM_TTEE:
		return "TTEE";
	case ARM_TTET:
		return "TTET";
	case ARM_TEEE:
		return "TEEE";
	case ARM_TEET:
		return "TEET";
	case ARM_TETT:
		return "TETT";
	case ARM_TETE:
		return "TETE";
	}
}

#define GET_MCLASSSYSREG_IMPL
#include "ARMGenSystemRegister.inc"

const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegBy12bitSYSmValue(unsigned SYSm)
{
	return ARMSysReg_lookupMClassSysRegByM1Encoding12(SYSm);
}

// returns APSR with _<bits> qualifier.
// Note: ARMv7-M deprecates using MSR APSR without a _<bits> qualifier
const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegAPSRNonDeprecated(unsigned SYSm)
{
	return ARMSysReg_lookupMClassSysRegByM2M3Encoding8((1 << 9) |
							   (SYSm & 0xFF));
}

// lookup system registers using 8-bit SYSm value
const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegBy8bitSYSmValue(unsigned SYSm)
{
	return ARMSysReg_lookupMClassSysRegByM2M3Encoding8((1 << 8) |
							   (SYSm & 0xFF));
}
