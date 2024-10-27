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

//===- ARCInfo.h - Additional ARC Info --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone helper functions and enum definitions for
// the ARC target useful for the compiler back-end and the MC libraries.
// As such, it deliberately does not include references to LLVM core
// code gen types, passes, etc..
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_ARC_MCTARGETDESC_ARCINFO_H
#define LLVM_LIB_TARGET_ARC_MCTARGETDESC_ARCINFO_H

// Enums corresponding to ARC condition codes
// CS namespace begin: ARCCC

typedef enum ARCCondCode {
	ARCCC_AL = 0x0,
	ARCCC_EQ = 0x1,
	ARCCC_NE = 0x2,
	ARCCC_P = 0x3,
	ARCCC_N = 0x4,
	ARCCC_LO = 0x5,
	ARCCC_HS = 0x6,
	ARCCC_VS = 0x7,
	ARCCC_VC = 0x8,
	ARCCC_GT = 0x9,
	ARCCC_GE = 0xa,
	ARCCC_LT = 0xb,
	ARCCC_LE = 0xc,
	ARCCC_HI = 0xd,
	ARCCC_LS = 0xe,
	ARCCC_PNZ = 0xf,
	ARCCC_Z = 0x11, // Low 4-bits = EQ
	ARCCC_NZ = 0x12 // Low 4-bits = NE
} ARCCC_CondCode;

typedef enum BRCondCode {
	ARCCC_BREQ = 0x0,
	ARCCC_BRNE = 0x1,
	ARCCC_BRLT = 0x2,
	ARCCC_BRGE = 0x3,
	ARCCC_BRLO = 0x4,
	ARCCC_BRHS = 0x5
} ARCCC_BRCondCode;

// CS namespace end: ARCCC

// end namespace ARCCC

// end namespace llvm

#endif
