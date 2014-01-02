#ifndef CAPSTONE_MIPS_INSTPRINTER_H_1A2B652FE84A432495E4009FA1C8E2C3
#define CAPSTONE_MIPS_INSTPRINTER_H_1A2B652FE84A432495E4009FA1C8E2C3

//=== MipsInstPrinter.h - Convert Mips MCInst to assembly syntax -*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints a Mips MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../MCInst.h"
#include "../../SStream.h"

void Mips_printInst(MCInst *MI, SStream *O, void *info);

#endif
