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

//===- XtensaInstPrinter.cpp - Convert Xtensa MCInst to asm syntax --------===//
//
//                     The LLVM Compiler Infrastructure
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an Xtensa MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInstPrinter.h"
#include "../../SStream.h"
#include "./priv.h"
#include "../../Mapping.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"
static MnemonicBitsInfo getMnemonic(MCInst *MI, SStream *O);
static const char *getRegisterName(unsigned RegNo);

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	const MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isReg(MC)) {
		SStream_concat0(O, getRegisterName(MCOperand_getReg(MC)));

	} else if (MCOperand_isImm(MC)) {
		printInt64(O, MCOperand_getImm(MC));
	} else if (MCOperand_isExpr(MC)) {
		printExpr(MCOperand_getExpr(MC), O);
	} else
		report_fatal_error("Invalid operand");
}

static inline void printMemOperand(MCInst *MI, int OpNum, SStream *OS)
{
	SStream_concat0(OS, getRegisterName(MCOperand_getReg(
				    MCInst_getOperand(MI, (OpNum)))));
	SStream_concat0(OS, ", ");
	printOperand(MI, OpNum + 1, OS);
}

static inline void printBranchTarget(MCInst *MI, int OpNum, SStream *OS)
{
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else
		assert(0 && "Invalid operand");
}

static inline void printJumpTarget(MCInst *MI, int OpNum, SStream *OS)
{
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else
		assert(0 && "Invalid operand");
	;
}

static inline void printCallOperand(MCInst *MI, int OpNum, SStream *OS)
{
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else
		assert(0 && "Invalid operand");
}

static inline void printL32RTarget(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		int64_t InstrOff = Value & 0x3;
		Value -= InstrOff;

		Value += ((InstrOff + 0x3) & 0x4) - InstrOff;
		SStream_concat0(O, ". ");
		printInt64(O, Value);
	} else
		assert(0 && "Invalid operand");
}

static inline void printImm8_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else {
		printOperand(MI, OpNum, O);
	}
}

static inline void printImm8_sh8_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm12m_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printUimm4_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printUimm5_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printShimm1_31_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm1_16_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printB4const_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		switch (Value) {
		case -1:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 10:
		case 12:
		case 16:
		case 32:
		case 64:
		case 128:
		case 256:
			break;
		default:
			break;
		}
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printB4constu_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		switch (Value) {
		case 32768:
		case 65536:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 10:
		case 12:
		case 16:
		case 32:
		case 64:
		case 128:
		case 256:
			break;
		default:
			break;
		}
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

#include "XtensaGenAsmWriter.inc"

const char *Xtensa_LLVM_getRegisterName(unsigned RegNo)
{
	return getRegisterName(RegNo);
}

void Xtensa_LLVM_printInstruction(MCInst *MI, uint64_t Address, SStream *O)
{
	printInstruction(MI, Address, O);
}
