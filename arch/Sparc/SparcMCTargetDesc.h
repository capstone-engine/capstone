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

//===-- SparcMCTargetDesc.h - Sparc Target Descriptions ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides Sparc specific target descriptions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SPARC_MCTARGETDESC_SPARCMCTARGETDESC_H
#define LLVM_LIB_TARGET_SPARC_MCTARGETDESC_SPARCMCTARGETDESC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../LEB128.h"
#include "../../MathExtras.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

// Defines symbolic names for Sparc v9 ASI tag names.
// CS namespace begin: SparcASITag

typedef union sparc_sys_imm {
	sparc_asi asi;
	unsigned raw_val;
} sparc_sys_imm;

typedef struct {
	const char *Name;
	sparc_sys_imm imm;
	const char *AltName;
	sparc_sys_imm alt_imm;
	unsigned Encoding;
} Sparc_ASITag_ASITag;

#define GET_ASITAG_DECL
#include "SparcGenSystemOperands.inc"

// CS namespace end: SparcASITag

// end namespace SparcASITag
// End llvm namespace

// Defines symbolic names for Sparc registers.  This defines a mapping from
// register name to register number.
//
#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "SparcGenRegisterInfo.inc"

// Defines symbolic names for the Sparc instructions.
//
#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_HELPER_DECLS
#include "SparcGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "SparcGenSubtargetInfo.inc"

#endif
