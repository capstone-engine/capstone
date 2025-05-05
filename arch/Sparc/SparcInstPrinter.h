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

//===-- SparcInstPrinter.h - Convert Sparc MCInst to assembly syntax ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an Sparc MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SPARC_MCTARGETDESC_SPARCINSTPRINTER_H
#define LLVM_LIB_TARGET_SPARC_MCTARGETDESC_SPARCINSTPRINTER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "SparcMCTargetDesc.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

bool printSparcAliasInstr(MCInst *MI, SStream *OS);
void printMemOperand(MCInst *MI, int opNum, SStream *OS);
void printCCOperand(MCInst *MI, int opNum, SStream *OS);
bool printGetPCX(MCInst *MI, unsigned OpNo, SStream *OS);
void printMembarTag(MCInst *MI, int opNum, SStream *O);
void printASITag(MCInst *MI, int opNum, SStream *O);
;
// end namespace llvm

#endif
