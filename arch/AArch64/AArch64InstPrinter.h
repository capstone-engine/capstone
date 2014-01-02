#ifndef CAPSTONE_LLVM_AARCH64INSTPRINTER_H_F852AF6EA5AD4E9A8BCD6B53F8B11508
#define CAPSTONE_LLVM_AARCH64INSTPRINTER_H_F852AF6EA5AD4E9A8BCD6B53F8B11508

//===-- AArch64InstPrinter.h - Convert AArch64 MCInst to assembly syntax --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an AArch64 MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

void AArch64_printInst(MCInst *MI, SStream *O, void *);

void AArch64_post_printer(csh handle, cs_insn *pub_insn, char *insn_asm);

#endif
