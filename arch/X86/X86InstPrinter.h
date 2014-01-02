#ifndef CAPSTONE_X86_INSTPRINTER_H_A5E4EA801A6A4CDC9020D175B449AABD
#define CAPSTONE_X86_INSTPRINTER_H_A5E4EA801A6A4CDC9020D175B449AABD

//= X86IntelInstPrinter.h - Convert X86 MCInst to assembly syntax -*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an X86 MCInst to Intel style .s file syntax.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../MCInst.h"
#include "../../SStream.h"

void X86_Intel_printInst(MCInst *MI, SStream *OS, void *Info);
void X86_ATT_printInst(MCInst *MI, SStream *OS, void *Info);

#endif
