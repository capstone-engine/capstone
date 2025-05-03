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

//===-- SparcInstPrinter.cpp - Convert Sparc MCInst to assembly syntax -----==//
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "SparcInstrInfo.h"
#include "SparcInstPrinter.h"
#include "SparcLinkage.h"
#include "SparcMCTargetDesc.h"
#include "SparcMapping.h"
#include "SparcRegisterInfo.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

// The generated AsmMatcher SparcGenAsmWriter uses "Sparc" as the target
// namespace. But SPARC backend uses "SP" as its namespace.

// CS namespace begin: Sparc

// CS namespace end: Sparc

#define GET_INSTRUCTION_NAME
#define PRINT_ALIAS_INSTR
#include "SparcGenAsmWriter.inc"

bool isV9()
{
	return (STI.hasFeature(Sparc_FeatureV9)) != 0;
}

void printRegName(SStream *OS, MCRegister Reg)
{
	SStream_concat1(OS, '%');
	SStream_concat0(OS, getRegisterName(Reg));
}

void printRegName(SStream *OS, MCRegister Reg, unsigned AltIdx)
{
	SStream_concat1(OS, '%');
	SStream_concat0(OS, getRegisterName(Reg, AltIdx));
}

void printInst(MCInst *MI, uint64_t Address, StringRef Annot, SStream *O)
{
	if (!printAliasInstr(MI, Address, O) &&
	    !printSparcAliasInstr(MI, STI, O))
		printInstruction(MI, Address, O);
	;
}

bool printSparcAliasInstr(MCInst *MI, SStream *O)
{
	switch (MCInst_getOpcode(MI)) {
	default:
		return false;
	case SP_JMPLrr:
	case SP_JMPLri: {
		if (MCInst_getNumOperands(MI) != 3)
			return false;
		if (!MCOperand_isReg(MCInst_getOperand(MI, (0))))
			return false;
		switch (MCOperand_getReg(MCInst_getOperand(MI, (0)))) {
		default:
			return false;
		case SP_G0: // jmp $addr | ret | retl
			if (MCOperand_isImm(MCInst_getOperand(MI, (2))) &&
			    MCOperand_getImm(MCInst_getOperand(MI, (2))) == 8) {
				switch (MCOperand_getReg(
					MCInst_getOperand(MI, (1)))) {
				default:
					break;
				case SP_I7:
					SStream_concat0(O, "\tret");
					return true;
				case SP_O7:
					SStream_concat0(O, "\tretl");
					return true;
				}
			}
			SStream_concat0(O, "\tjmp ");
			printMemOperand(MI, 1, O);
			return true;
		case SP_O7: // call $addr
			SStream_concat0(O, "\tcall ");
			printMemOperand(MI, 1, O);
			return true;
		}
	}
	case SP_V9FCMPS:
	case SP_V9FCMPD:
	case SP_V9FCMPQ:
	case SP_V9FCMPES:
	case SP_V9FCMPED:
	case SP_V9FCMPEQ: {
		if (isV9(STI) || (MCInst_getNumOperands(MI) != 3) ||
		    (!MCOperand_isReg(MCInst_getOperand(MI, (0)))) ||
		    (MCOperand_getReg(MCInst_getOperand(MI, (0))) != SP_FCC0))
			return false;
		// if V8, skip printing %fcc0.
		switch (MCInst_getOpcode(MI)) {
		default:
		case SP_V9FCMPS:
			SStream_concat0(O, "\tfcmps ");
			break;
		case SP_V9FCMPD:
			SStream_concat0(O, "\tfcmpd ");
			break;
		case SP_V9FCMPQ:
			SStream_concat0(O, "\tfcmpq ");
			break;
		case SP_V9FCMPES:
			SStream_concat0(O, "\tfcmpes ");
			break;
		case SP_V9FCMPED:
			SStream_concat0(O, "\tfcmped ");
			break;
		case SP_V9FCMPEQ:
			SStream_concat0(O, "\tfcmpeq ");
			break;
		}
		printOperand(MI, 1, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 2, O);
		return true;
	}
	}
}

void printOperand(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (opNum));

	if (MCOperand_isReg(MO)) {
		unsigned Reg = MCOperand_getReg(MO);
		if (isV9(STI))
			printRegName(O, Reg, SP_RegNamesStateReg);
		else
			printRegName(O, Reg);
		return;
	}

	if (MCOperand_isImm(MO)) {
		switch (MCInst_getOpcode(MI)) {
		default:
			SStream_concat0(O, (int)MCOperand_getImm(MO));
			return;

		case SP_TICCri: // Fall through
		case SP_TICCrr: // Fall through
		case SP_TRAPri: // Fall through
		case SP_TRAPrr: // Fall through
		case SP_TXCCri: // Fall through
		case SP_TXCCrr: // Fall through
			// Only seven-bit values up to 127.
			SStream_concat0(O, ((int)MCOperand_getImm(MO) & 0x7f));
			return;
		}
	}

	CS_ASSERT(MCOperand_isExpr(MO) &&
		  "Unknown operand kind in printOperand");
	MCOperand_getExpr(MO)->print(O, &MAI);
}

void printMemOperand(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *Op1 = MCInst_getOperand(MI, (opNum));
	MCOperand *Op2 = MCInst_getOperand(MI, (opNum + 1));

	bool PrintedFirstOperand = false;
	if (MCOperand_isReg(Op1) && MCOperand_getReg(Op1) != SP_G0) {
		printOperand(MI, opNum, O);
		PrintedFirstOperand = true;
	}

	// Skip the second operand iff it adds nothing (literal 0 or %g0) and we've
	// already printed the first one
	const bool SkipSecondOperand =
		PrintedFirstOperand &&
		((MCOperand_isReg(Op2) && MCOperand_getReg(Op2) == SP_G0) ||
		 (MCOperand_isImm(Op2) && MCOperand_getImm(Op2) == 0));

	if (!SkipSecondOperand) {
		if (PrintedFirstOperand)
			SStream_concat0(O, "+");

		printOperand(MI, opNum + 1, O);
	}
}

void printCCOperand(MCInst *MI, int opNum, SStream *O)
{
	int CC = (int)MCOperand_getImm(MCInst_getOperand(MI, (opNum)));
	switch (MCInst_getOpcode(MI)) {
	default:
		break;
	case SP_FBCOND:
	case SP_FBCONDA:
	case SP_FBCOND_V9:
	case SP_FBCONDA_V9:
	case SP_BPFCC:
	case SP_BPFCCA:
	case SP_BPFCCNT:
	case SP_BPFCCANT:
	case SP_MOVFCCrr:
	case SP_V9MOVFCCrr:
	case SP_MOVFCCri:
	case SP_V9MOVFCCri:
	case SP_FMOVS_FCC:
	case SP_V9FMOVS_FCC:
	case SP_FMOVD_FCC:
	case SP_V9FMOVD_FCC:
	case SP_FMOVQ_FCC:
	case SP_V9FMOVQ_FCC:
		// Make sure CC is a fp conditional flag.
		CC = (CC < SPCC_FCC_BEGIN) ? (CC + SPCC_FCC_BEGIN) : CC;
		break;
	case SP_CBCOND:
	case SP_CBCONDA:
		// Make sure CC is a cp conditional flag.
		CC = (CC < SPCC_CPCC_BEGIN) ? (CC + SPCC_CPCC_BEGIN) : CC;
		break;
	case SP_BPR:
	case SP_BPRA:
	case SP_BPRNT:
	case SP_BPRANT:
	case SP_MOVRri:
	case SP_MOVRrr:
	case SP_FMOVRS:
	case SP_FMOVRD:
	case SP_FMOVRQ:
		// Make sure CC is a register conditional flag.
		CC = (CC < SPCC_REG_BEGIN) ? (CC + SPCC_REG_BEGIN) : CC;
		break;
	}
	SStream_concat0(O, SPARCCondCodeToString((SPCC_CondCodes)CC));
}

bool printGetPCX(MCInst *MI, unsigned opNum, SStream *O)
{
	CS_ASSERT(0 && "FIXME: Implement SparcInstPrinter::printGetPCX.");
	return true;
}

void printMembarTag(MCInst *MI, int opNum, SStream *O)
{
	static const char *const TagNames[] = { "#LoadLoad",  "#StoreLoad",
						"#LoadStore", "#StoreStore",
						"#Lookaside", "#MemIssue",
						"#Sync" };

	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (opNum)));

	if (Imm > 127) {
		SStream_concat0(O, Imm);
		return;
	}

	bool First = true;
	for (unsigned i = 0; i < sizeof(TagNames); i++) {
		if (Imm & (1 << i)) {
			SStream_concat(O, "%s", (First ? "" : " | "));
			SStream_concat0(O, TagNames[i]);
			First = false;
		}
	}
}

void printASITag(MCInst *MI, int opNum, SStream *O)
{
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (opNum)));
	auto ASITag = SparcASITag_lookupASITagByEncoding(Imm);
	if (isV9(STI) && ASITag) {
		SStream_concat1(O, '#');
		SStream_concat0(O, ASITag->Name);
	} else
		SStream_concat0(O, Imm);
}
