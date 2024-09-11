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

//===-- AArch64BaseInfo.cpp - AArch64 Base encoding information------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides basic encoding and assembly information for AArch64.
//
//===----------------------------------------------------------------------===//
#include <capstone/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AArch64BaseInfo.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define GET_AT_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_AT_IMPL

#define GET_DBNXS_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_DBNXS_IMPL

#define GET_DB_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_DB_IMPL

#define GET_DC_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_DC_IMPL

#define GET_IC_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_IC_IMPL

#define GET_ISB_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_ISB_IMPL

#define GET_TSB_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_TSB_IMPL

#define GET_PRCTX_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_PRCTX_IMPL

#define GET_PRFM_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_PRFM_IMPL

#define GET_SVEPRFM_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_SVEPRFM_IMPL

#define GET_RPRFM_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_RPRFM_IMPL

// namespace AArch64RPRFM
// namespace llvm

#define GET_SVEPREDPAT_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_SVEPREDPAT_IMPL

#define GET_SVEVECLENSPECIFIER_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_SVEVECLENSPECIFIER_IMPL

// namespace AArch64SVEVecLenSpecifier
// namespace llvm

#define GET_EXACTFPIMM_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_EXACTFPIMM_IMPL

#define GET_PSTATEIMM0_15_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_PSTATEIMM0_15_IMPL

#define GET_PSTATEIMM0_1_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_PSTATEIMM0_1_IMPL

#define GET_PSB_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_PSB_IMPL

#define GET_BTI_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_BTI_IMPL

#define SysReg AArch64SysReg_SysReg
#define GET_SYSREG_IMPL
#include "AArch64GenSystemOperands.inc"
#undef GET_SYSREG_IMPL

#undef SysReg

// return a string representing the number X
// NOTE: result must be big enough to contain the data
static void utostr(uint64_t X, bool isNeg, char *result)
{
	char Buffer[22];
	char *BufPtr = Buffer + 21;

	Buffer[21] = '\0';
	if (X == 0)
		*--BufPtr = '0'; // Handle special case...

	while (X) {
		*--BufPtr = X % 10 + '0';
		X /= 10;
	}

	if (isNeg)
		*--BufPtr = '-'; // Add negative sign...

	// suppose that result is big enough
	strncpy(result, BufPtr, sizeof(Buffer));
}

// NOTE: result must be big enough to contain the result
void AArch64SysReg_genericRegisterString(uint32_t Bits, char *result)
{
	CS_ASSERT_RET(Bits < 0x10000);
	char Op0Str[32], Op1Str[32], CRnStr[32], CRmStr[32], Op2Str[32];
	int dummy;
	uint32_t Op0 = (Bits >> 14) & 0x3;
	uint32_t Op1 = (Bits >> 11) & 0x7;
	uint32_t CRn = (Bits >> 7) & 0xf;
	uint32_t CRm = (Bits >> 3) & 0xf;
	uint32_t Op2 = Bits & 0x7;

	utostr(Op0, false, Op0Str);
	utostr(Op1, false, Op1Str);
	utostr(Op2, false, Op2Str);
	utostr(CRn, false, CRnStr);
	utostr(CRm, false, CRmStr);

	dummy = cs_snprintf(result, AARCH64_GRS_LEN, "s%s_%s_c%s_c%s_%s",
			    Op0Str, Op1Str, CRnStr, CRmStr, Op2Str);
	(void)dummy;
}

#define GET_TLBITable_IMPL

#include "AArch64GenSystemOperands.inc"
#undef GET_TLBITable_IMPL

#define GET_SVCR_IMPL

#include "AArch64GenSystemOperands.inc"
#undef GET_SVCR_IMPL
