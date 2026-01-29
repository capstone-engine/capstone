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

#include "../../MCInstPrinter.h"
#include "../../Mapping.h"
#include "SparcInstPrinter.h"
#include "SparcLinkage.h"
#include "SparcMCTargetDesc.h"
#include "SparcMapping.h"
#include "SparcDisassemblerExtension.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

static void printCustomAliasOperand(MCInst *MI, uint64_t Address,
				    unsigned OpIdx, unsigned PrintMethodIdx,
				    SStream *OS);
static void printOperand(MCInst *MI, int opNum, SStream *O);

#define GET_INSTRUCTION_NAME
#define PRINT_ALIAS_INSTR
#include "SparcGenAsmWriter.inc"

static void printRegName(SStream *OS, MCRegister Reg)
{
	SStream_concat1(OS, '%');
	SStream_concat0(OS, getRegisterName(Reg, Sparc_NoRegAltName));
}

static void printRegNameAlt(SStream *OS, MCRegister Reg, unsigned AltIdx)
{
	SStream_concat1(OS, '%');
	SStream_concat0(OS, getRegisterName(Reg, AltIdx));
}

static void printInst(MCInst *MI, uint64_t Address, SStream *O)
{
	bool isAlias = false;
	bool useAliasDetails = map_use_alias_details(MI);
	map_set_fill_detail_ops(MI, useAliasDetails);

	if (!printAliasInstr(MI, Address, O) && !printSparcAliasInstr(MI, O)) {
		MCInst_setIsAlias(MI, false);
	} else {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		if (useAliasDetails) {
			return;
		}
	}

	if (!isAlias || !useAliasDetails) {
		map_set_fill_detail_ops(MI, !(isAlias && useAliasDetails));
		if (isAlias)
			SStream_Close(O);
		printInstruction(MI, Address, O);
		if (isAlias)
			SStream_Open(O);
	}
}

bool printSparcAliasInstr(MCInst *MI, SStream *O)
{
	switch (MCInst_getOpcode(MI)) {
	default:
		return false;
	case Sparc_JMPLrr:
	case Sparc_JMPLri: {
		if (MCInst_getNumOperands(MI) != 3)
			return false;
		if (!MCOperand_isReg(MCInst_getOperand(MI, (0))))
			return false;
		switch (MCOperand_getReg(MCInst_getOperand(MI, (0)))) {
		default:
			return false;
		case Sparc_G0: // jmp $addr | ret | retl
			if (MCOperand_isImm(MCInst_getOperand(MI, (2))) &&
			    MCOperand_getImm(MCInst_getOperand(MI, (2))) == 8) {
				switch (MCOperand_getReg(
					MCInst_getOperand(MI, (1)))) {
				default:
					break;
				case Sparc_I7:
					SStream_concat0(O, "\tret");
					return true;
				case Sparc_O7:
					SStream_concat0(O, "\tretl");
					return true;
				}
			}
			SStream_concat0(O, "\tjmp ");
			printMemOperand(MI, 1, O);
			return true;
		case Sparc_O7: // call $addr
			SStream_concat0(O, "\tcall ");
			printMemOperand(MI, 1, O);
			return true;
		}
	}
	case Sparc_V9FCMPS:
	case Sparc_V9FCMPD:
	case Sparc_V9FCMPQ:
	case Sparc_V9FCMPES:
	case Sparc_V9FCMPED:
	case Sparc_V9FCMPEQ: {
		if (Sparc_getFeatureBits(MI->csh->mode, Sparc_FeatureV9) ||
		    (MCInst_getNumOperands(MI) != 3) ||
		    (!MCOperand_isReg(MCInst_getOperand(MI, (0)))) ||
		    (MCOperand_getReg(MCInst_getOperand(MI, (0))) !=
		     Sparc_FCC0))
			return false;
		// if V8, skip printing %fcc0.
		switch (MCInst_getOpcode(MI)) {
		default:
		case Sparc_V9FCMPS:
			SStream_concat0(O, "\tfcmps ");
			break;
		case Sparc_V9FCMPD:
			SStream_concat0(O, "\tfcmpd ");
			break;
		case Sparc_V9FCMPQ:
			SStream_concat0(O, "\tfcmpq ");
			break;
		case Sparc_V9FCMPES:
			SStream_concat0(O, "\tfcmpes ");
			break;
		case Sparc_V9FCMPED:
			SStream_concat0(O, "\tfcmped ");
			break;
		case Sparc_V9FCMPEQ:
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

static void printOperand(MCInst *MI, int opNum, SStream *O)
{
	Sparc_add_cs_detail_0(MI, Sparc_OP_GROUP_Operand, opNum);
	MCOperand *MO = MCInst_getOperand(MI, (opNum));

	if (MCOperand_isReg(MO)) {
		unsigned Reg = MCOperand_getReg(MO);
		if (Sparc_getFeatureBits(MI->csh->mode, Sparc_FeatureV9))
			printRegNameAlt(O, Reg, Sparc_RegNamesStateReg);
		else
			printRegName(O, Reg);
		return;
	}

	if (MCOperand_isImm(MO)) {
		switch (MCInst_getOpcode(MI)) {
		default:
			printInt32(O, (int)MCOperand_getImm(MO));
			return;

		case Sparc_TICCri: // Fall through
		case Sparc_TICCrr: // Fall through
		case Sparc_TRAPri: // Fall through
		case Sparc_TRAPrr: // Fall through
		case Sparc_TXCCri: // Fall through
		case Sparc_TXCCrr: // Fall through
			// Only seven-bit values up to 127.
			printInt8(O, ((int)MCOperand_getImm(MO) & 0x7f));
			return;
		}
	}

	CS_ASSERT(MCOperand_isExpr(MO) &&
		  "Unknown operand kind in printOperand");
}

void printMemOperand(MCInst *MI, int opNum, SStream *O)
{
	Sparc_add_cs_detail_0(MI, Sparc_OP_GROUP_MemOperand, opNum);
	MCOperand *Op1 = MCInst_getOperand(MI, (opNum));
	MCOperand *Op2 = MCInst_getOperand(MI, (opNum + 1));

	bool PrintedFirstOperand = false;
	if (MCOperand_isReg(Op1) && MCOperand_getReg(Op1) != Sparc_G0) {
		printOperand(MI, opNum, O);
		PrintedFirstOperand = true;
	}

	// Skip the second operand iff it adds nothing (literal 0 or %g0) and we've
	// already printed the first one
	const bool SkipSecondOperand =
		PrintedFirstOperand &&
		((MCOperand_isReg(Op2) && MCOperand_getReg(Op2) == Sparc_G0) ||
		 (MCOperand_isImm(Op2) && MCOperand_getImm(Op2) == 0));

	if (!SkipSecondOperand) {
		if (PrintedFirstOperand)
			SStream_concat0(O, "+");

		printOperand(MI, opNum + 1, O);
	}
}

void printCCOperand(MCInst *MI, int opNum, SStream *O)
{
	Sparc_add_cs_detail_0(MI, Sparc_OP_GROUP_CCOperand, opNum);
	int CC = (int)MCOperand_getImm(MCInst_getOperand(MI, (opNum)));
	switch (MCInst_getOpcode(MI)) {
	default:
		break;
	case Sparc_FBCOND:
	case Sparc_FBCONDA:
	case Sparc_FBCOND_V9:
	case Sparc_FBCONDA_V9:
	case Sparc_BPFCC:
	case Sparc_BPFCCA:
	case Sparc_BPFCCNT:
	case Sparc_BPFCCANT:
	case Sparc_MOVFCCrr:
	case Sparc_V9MOVFCCrr:
	case Sparc_MOVFCCri:
	case Sparc_V9MOVFCCri:
	case Sparc_FMOVS_FCC:
	case Sparc_V9FMOVS_FCC:
	case Sparc_FMOVD_FCC:
	case Sparc_V9FMOVD_FCC:
	case Sparc_FMOVQ_FCC:
	case Sparc_V9FMOVQ_FCC:
		// Make sure CC is a fp conditional flag.
		CC = (CC < SPARC_CC_FCC_BEGIN) ? (CC + SPARC_CC_FCC_BEGIN) : CC;
		break;
	case Sparc_CBCOND:
	case Sparc_CBCONDA:
		// Make sure CC is a cp conditional flag.
		CC = (CC < SPARC_CC_CPCC_BEGIN) ? (CC + SPARC_CC_CPCC_BEGIN) :
						  CC;
		break;
	case Sparc_BPR:
	case Sparc_BPRA:
	case Sparc_BPRNT:
	case Sparc_BPRANT:
	case Sparc_MOVRri:
	case Sparc_MOVRrr:
	case Sparc_FMOVRS:
	case Sparc_FMOVRD:
	case Sparc_FMOVRQ:
		// Make sure CC is a register conditional flag.
		CC = (CC < SPARC_CC_REG_BEGIN) ? (CC + SPARC_CC_REG_BEGIN) : CC;
		break;
	}
	SStream_concat0(O, SPARCCondCodeToString((sparc_cc)CC));
}

bool printGetPCX(MCInst *MI, unsigned opNum, SStream *O)
{
	printf("FIXME: Implement SparcInstPrinter::printGetPCX.");
	return true;
}

void printMembarTag(MCInst *MI, int opNum, SStream *O)
{
	Sparc_add_cs_detail_0(MI, Sparc_OP_GROUP_MembarTag, opNum);
	static const char *const TagNames[] = { "#LoadLoad",  "#StoreLoad",
						"#LoadStore", "#StoreStore",
						"#Lookaside", "#MemIssue",
						"#Sync" };

	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (opNum)));

	if (Imm > 127) {
		printUInt32(O, Imm);
		return;
	}

	bool First = true;
	for (unsigned i = 0; i < ARR_SIZE(TagNames); i++) {
		if (Imm & (1ull << i)) {
			SStream_concat(O, "%s", (First ? "" : " | "));
			SStream_concat0(O, TagNames[i]);
			First = false;
		}
	}
}

#define GET_ASITAG_IMPL
#include "SparcGenSystemOperands.inc"

void printASITag(MCInst *MI, int opNum, SStream *O)
{
	Sparc_add_cs_detail_0(MI, Sparc_OP_GROUP_ASITag, opNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (opNum)));
	const Sparc_ASITag_ASITag *ASITag =
		Sparc_ASITag_lookupASITagByEncoding(Imm);
	if (Sparc_getFeatureBits(MI->csh->mode, Sparc_FeatureV9) && ASITag) {
		SStream_concat1(O, '#');
		SStream_concat0(O, ASITag->Name);
	} else
		printUInt32(O, Imm);
}

void Sparc_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			  SStream *O)
{
	printInst(MI, Address, O);
}

const char *Sparc_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}
