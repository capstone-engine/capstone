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

//===- ARCInstPrinter.cpp - ARC MCInst to assembly syntax -------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an ARC MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "ARCInfo.h"
#include "../../SStream.h"
#include "../../MCInst.h"
#include "../../MCInstPrinter.h"

#include "ARCInfo.h"
#include "ARCInstPrinter.h"
#include "ARCLinkage.h"
#include "ARCMapping.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

#include "ARCGenAsmWriter.inc"

static const char *ARCBRCondCodeToString(ARCCC_BRCondCode BRCC)
{
	switch (BRCC) {
	case ARCCC_BREQ:
		return "eq";
	case ARCCC_BRNE:
		return "ne";
	case ARCCC_BRLT:
		return "lt";
	case ARCCC_BRGE:
		return "ge";
	case ARCCC_BRLO:
		return "lo";
	case ARCCC_BRHS:
		return "hs";
	}
	assert(0 && "Unknown condition code passed");
}

static const char *ARCCondCodeToString(ARCCC_CondCode CC)
{
	switch (CC) {
	case ARCCC_EQ:
		return "eq";
	case ARCCC_NE:
		return "ne";
	case ARCCC_P:
		return "p";
	case ARCCC_N:
		return "n";
	case ARCCC_HS:
		return "hs";
	case ARCCC_LO:
		return "lo";
	case ARCCC_GT:
		return "gt";
	case ARCCC_GE:
		return "ge";
	case ARCCC_VS:
		return "vs";
	case ARCCC_VC:
		return "vc";
	case ARCCC_LT:
		return "lt";
	case ARCCC_LE:
		return "le";
	case ARCCC_HI:
		return "hi";
	case ARCCC_LS:
		return "ls";
	case ARCCC_PNZ:
		return "pnz";
	case ARCCC_AL:
		return "al";
	case ARCCC_NZ:
		return "nz";
	case ARCCC_Z:
		return "z";
	}
	assert(0 && "Unknown condition code passed");
}

void printRegName(SStream *OS, MCRegister Reg)
{
	SStream_concat0(OS, getRegisterName(Reg));
}

void printInst(MCInst *MI, uint64_t Address, const char *Annot, SStream *O)
{
	printInstruction(MI, Address, O);
}

// static void printExpr(const MCExpr *Expr, const MCAsmInfo *MAI, SStream *OS)
// {
// 	int Offset = 0;
// 	const MCSymbolRefExpr *SRE;

// 	if (const auto *CE = (MCConstantExpr)(Expr)) {
// 		SStream_concat0(OS, "0x");
// 		OS.write_hex(CE->getValue());
// 		return;
// 	}

// 	if (const auto *BE = (MCBinaryExpr)(Expr)) {
// 		SRE = (MCSymbolRefExpr)(BE->getLHS());
// 		const auto *CE = (MCConstantExpr)(BE->getRHS());
// 		CS_ASSERT(
// 			(SRE && CE && "Binary expression must be sym+const."));
// 		Offset = CE->getValue();
// 	} else {
// 		SRE = (MCSymbolRefExpr)(Expr);
// 		CS_ASSERT((SRE && "Unexpected MCExpr type."));
// 	}
// 	CS_ASSERT((SRE->getKind() == MCSymbolRefExpr_VK_None));

// 	// Symbols are prefixed with '@'
// 	SStream_concat0(OS, "@");

// 	// SRE->getSymbol().print(OS, MAI);

// 	if (Offset) {
// 		if (Offset > 0)
// 			SStream_concat0(OS, "+");

// 		SStream_concat0(OS, Offset);
// 	}
// }

void printOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_Operand, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
		return;
	}

	if (MCOperand_isImm(Op) || MCOperand_isExpr(Op)) {
		printInt64(O, MCOperand_getImm(Op));
		return;
	}

	// CS_ASSERT((MCOperand_isExpr(Op) &&
	// 	   "unknown operand kind in printOperand"));
	// printExpr(MCOperand_getExpr(Op), &MAI, O);
}

void printMemOperandRI(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_MemOperandRI, OpNum);
	MCOperand *base = MCInst_getOperand(MI, (OpNum));
	MCOperand *offset = MCInst_getOperand(MI, (OpNum + 1));
	CS_ASSERT((MCOperand_isReg(base) && "Base should be register."));
	CS_ASSERT((MCOperand_isImm(offset) && "Offset should be immediate."));
	printRegName(O, MCOperand_getReg(base));
	SStream_concat(O, "%s", ",");
	printInt64(O, MCOperand_getImm(offset));
}

void printPredicateOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_PredicateOperand, OpNum);

	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	CS_ASSERT((MCOperand_isImm(Op) && "Predicate operand is immediate."));
	SStream_concat0(
		O, ARCCondCodeToString((ARCCC_CondCode)MCOperand_getImm(Op)));
}

void printBRCCPredicateOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_BRCCPredicateOperand, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	CS_ASSERT((MCOperand_isImm(Op) && "Predicate operand is immediate."));
	SStream_concat0(O, ARCBRCondCodeToString(
				   (ARCCC_BRCondCode)MCOperand_getImm(Op)));
}

void printCCOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_CCOperand, OpNum);
	SStream_concat0(O, ARCCondCodeToString((ARCCC_CondCode)MCOperand_getImm(
				   MCInst_getOperand(MI, (OpNum)))));
}

void printU6ShiftedBy(unsigned ShiftBy, MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		unsigned Value = MCOperand_getImm(MO);
		unsigned Value2 = Value >> ShiftBy;
		if (Value2 > 0x3F || (Value2 << ShiftBy != Value)) {
			// SStream_concat(
			// 	errs(), "%s%s%s%s",
			// 	"!!! Instruction has out-of-range U6 immediate operand:\n",
			// 	"    Opcode is ", MCInst_getOpcode(MI),
			// 	"; operand value is ");
			// SStream_concat0(errs(), Value);
			// if (ShiftBy) {
			// 	SStream_concat(errs(), "%s%s", " scaled by ",
			// 		       (1 << ShiftBy));
			// 	SStream_concat0(errs(), "\n");
			// }
			CS_ASSERT((false && "instruction has wrong format"));
		}
	}
	printOperand(MI, OpNum, O);
}

void printU6(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, ARC_OP_GROUP_U6, OpNum);
	printU6ShiftedBy(0, MI, OpNum, O);
}

void ARC_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			      SStream *O)
{
	printInst(MI, Address, Annot, O);
}

const char *ARC_LLVM_getRegisterName(unsigned RegNo)
{
	return getRegisterName(RegNo);
}