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

//===-- RISCVInstPrinter.h - Convert RISC-V MCInst to asm syntax --*- C++ -*--//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints a RISC-V MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVINSTPRINTER_H
#define LLVM_LIB_TARGET_RISCV_MCTARGETDESC_RISCVINSTPRINTER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInstPrinter.h"
#include "../../cs_priv.h"
#include "../../SStream.h"
#include "RISCVBaseInfo.h"
#include "RISCVDisassemblerExtension.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

void printBranchOperand(MCInst *MI, uint64_t Address, unsigned OpNo,
			SStream *O);
void printCSRSystemRegister(MCInst *MI, unsigned OpNo, SStream *O);
void printFenceArg(MCInst *MI, unsigned OpNo, SStream *O);
void printFRMArg(MCInst *MI, unsigned OpNo, SStream *O);
void printFRMArgLegacy(MCInst *MI, unsigned OpNo, SStream *O);
void printFPImmOperand(MCInst *MI, unsigned OpNo, SStream *O);
void printZeroOffsetMemOp(MCInst *MI, unsigned OpNo, SStream *O);
void printVTypeI(MCInst *MI, unsigned OpNo, SStream *O);
void printVMaskReg(MCInst *MI, unsigned OpNo, SStream *O);
void printRlist(MCInst *MI, unsigned OpNo, SStream *O);
void printSpimm(MCInst *MI, unsigned OpNo, SStream *O);
void printRegReg(MCInst *MI, unsigned OpNo, SStream *O);

const char *RISCV_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);

const char *getSysRegName(unsigned reg);

bool isCompressed(MCInst *MI);

typedef enum {
#define GET_ENUM_VALUES_SysReg
#include "RISCVGenCSSystemOperandsEnum.inc"
} SysRegValue;

#endif
