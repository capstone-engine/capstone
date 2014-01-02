#ifndef CAPSTONE_ARM_INSTPRINTER_H_89FB780F13D14BC29CE5A4D8384149BA
#define CAPSTONE_ARM_INSTPRINTER_H_89FB780F13D14BC29CE5A4D8384149BA

//===- ARMInstPrinter.h - Convert ARM MCInst to assembly syntax -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an ARM MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

void ARM_printInst(MCInst *MI, SStream *O, void *Info);
void ARM_post_printer(csh handle, cs_insn *pub_insn, char *mnem);

#endif
