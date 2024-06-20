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

//===- LoongArchInstPrinter.cpp - Convert LoongArch MCInst to asm syntax --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an LoongArch MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "LoongArchMapping.h"
#include "LoongArchInstPrinter.h"

#define GET_SUBTARGETINFO_ENUM
#include "LoongArchGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "LoongArchGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "LoongArchGenRegisterInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "loongarch-asm-printer"

// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#include "LoongArchGenAsmWriter.inc"

static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O)
{
	if (!printAliasInstr(MI, Address, O))
		printInstruction(MI, Address, O);
	;
}

void LoongArch_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			      SStream *O)
{
	printInst(MI, Address, Annot, O);
}

const char *LoongArch_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}

static void printRegName(SStream *O, MCRegister Reg)
{
	SStream_concat1(O, '$');
	SStream_concat0(O, getRegisterName(Reg, LoongArch_RegAliasName));
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, LOONGARCH_OP_GROUP_OPERAND, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	if (MCOperand_isReg(MO)) {
		printRegName(O, MCOperand_getReg(MO));
		return;
	}

	if (MCOperand_isImm(MO)) {
		printInt64(O, MCOperand_getImm(MO));
		return;
	}

	assert(0 && "Expressions are not supported.");
}

static void printAtomicMemOp(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, LOONGARCH_OP_GROUP_ATOMICMEMOP, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	printRegName(O, MCOperand_getReg(MO));
}
