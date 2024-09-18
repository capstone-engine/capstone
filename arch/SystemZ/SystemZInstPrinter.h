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

//==- SystemZInstPrinter.h - Convert SystemZ MCInst to assembly --*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints a SystemZ MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SYSTEMZ_MCTARGETDESC_SYSTEMZINSTPRINTER_H
#define LLVM_LIB_TARGET_SYSTEMZ_MCTARGETDESC_SYSTEMZINSTPRINTER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInstPrinter.h"
#include "../../cs_priv.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

//
// All function declarations are moved for now to the C file to make them static.
//
void printOperandAsmInfo(const MCOperand *MO, const MCAsmInfo *MAI, SStream *O);
void printFormattedRegName(const MCAsmInfo *MAI, MCRegister Reg, SStream *O);

// Print various types of operand.
;

// end namespace llvm

#endif // LLVM_LIB_TARGET_SYSTEMZ_MCTARGETDESC_SYSTEMZINSTPRINTER_H
