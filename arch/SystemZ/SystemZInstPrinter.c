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

//===- SystemZInstPrinter.cpp - Convert SystemZ MCInst to assembly syntax -===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MathExtras.h"
#include "../../MCAsmInfo.h"

#include "SystemZMapping.h"
#include "SystemZInstPrinter.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

static void printAddress(const MCAsmInfo *MAI, MCRegister Base,
			 const MCOperand *DispMO, MCRegister Index, SStream *O);
static void printMCOperandMAI(const MCOperand *MO, const MCAsmInfo *MAI,
			      SStream *O);
static void printRegName(const MCInst *MI, SStream *O, MCRegister Reg);
static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O);
static void printOperand(MCInst *MI, int OpNum, SStream *O);
static void printU1ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU2ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU3ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU4ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printS8ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU8ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU12ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printS16ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU16ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printS32ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU32ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printU48ImmOperand(MCInst *MI, int OpNum, SStream *O);
static void printBDAddrOperand(MCInst *MI, int OpNum, SStream *O);
static void printBDXAddrOperand(MCInst *MI, int OpNum, SStream *O);
static void printBDLAddrOperand(MCInst *MI, int OpNum, SStream *O);
static void printBDRAddrOperand(MCInst *MI, int OpNum, SStream *O);
static void printBDVAddrOperand(MCInst *MI, int OpNum, SStream *O);
static void printPCRelOperand(MCInst *MI, uint64_t Address, int OpNum,
			      SStream *O);
static void printPCRelTLSOperand(MCInst *MI, uint64_t Address, int OpNum,
				 SStream *O);
// This forms part of the instruction name rather than the operand list.
// Print the mnemonic for a condition-code mask ("ne", "lh", etc.)
static void printCond4Operand(MCInst *MI, int OpNum, SStream *O);

#include "SystemZGenAsmWriter.inc"

#define DECLARE_printUImmOperand(N) \
	static void CONCAT(printUImmOperand, N)(MCInst * MI, int OpNum, \
						SStream *O);
DECLARE_printUImmOperand(1);
DECLARE_printUImmOperand(2);
DECLARE_printUImmOperand(3);
DECLARE_printUImmOperand(4);
DECLARE_printUImmOperand(8);
DECLARE_printUImmOperand(12);
DECLARE_printUImmOperand(16);
DECLARE_printUImmOperand(32);
DECLARE_printUImmOperand(48);

#define DECLARE_printSImmOperand(N) \
	static void CONCAT(printSImmOperand, N)(MCInst * MI, int OpNum, \
						SStream *O);
DECLARE_printSImmOperand(8);
DECLARE_printSImmOperand(16);
DECLARE_printSImmOperand(32);

static void printAddress(const MCAsmInfo *MAI, MCRegister Base,
			 const MCOperand *DispMO, MCRegister Index, SStream *O)
{
	printMCOperandMAI(DispMO, MAI, O);
	if (Base || Index) {
		SStream_concat0(O, "(");

		if (Index) {
			printFormattedRegName(MAI, Index, O);
			SStream_concat0(O, ",");
		}
		if (Base)
			printFormattedRegName(MAI, Base, O);
		else
			SStream_concat0(O, "0");

		SStream_concat0(O, ")");
	}
}

static void printMCOperandMAI(const MCOperand *MO, const MCAsmInfo *MAI,
			      SStream *O)
{
	if (MCOperand_isReg(MO)) {
		if (!MCOperand_getReg(MO))
			SStream_concat1(O, '0');
		else
			printFormattedRegName(MAI, MCOperand_getReg(MO), O);
	} else if (MCOperand_isImm(MO))
		printInt64(markup_OS(O, Markup_Immediate),
			   MCOperand_getImm(MO));
	else if (MCOperand_isExpr(MO))
		printExpr(O, MCOperand_getExpr(MO));
	else
		CS_ASSERT(0 && "Invalid operand");
}

static void printMCOperand(const MCInst *MI, const MCOperand *MO, SStream *O)
{
	if (MCOperand_isReg(MO)) {
		if (!MCOperand_getReg(MO))
			SStream_concat0(O, "0");

		else
			printFormattedRegName(&MI->MAI, MCOperand_getReg(MO),
					      O);
	} else if (MCOperand_isImm(MO))
		printInt64(markup_OS(O, Markup_Immediate),
			   MCOperand_getImm(MO));
	else if (MCOperand_isExpr(MO))
		printExpr(O, MCOperand_getExpr(MO));
	else
		CS_ASSERT_RET(0 && "Invalid operand");
}

void printFormattedRegName(const MCAsmInfo *MAI, MCRegister Reg, SStream *O)
{
	const char *RegName = getRegisterName(Reg);
	if (MAI->assemblerDialect == SYSTEMZASMDIALECT_AD_ATT) {
		// Skip register prefix so that only register number is left
		CS_ASSERT((isalpha(RegName[0]) && isdigit(RegName[1])));
		SStream_concat0(markup_OS(O, Markup_Register), (RegName + 1));
	} else
		SStream_concat1(markup_OS(O, Markup_Register), '%');
	SStream_concat0(markup_OS(O, Markup_Register), RegName);
}

static void printRegName(const MCInst *MI, SStream *O, MCRegister Reg)
{
	printFormattedRegName(&MI->MAI, Reg, O);
}

static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O)
{
	printInstruction(MI, Address, O);
}

#define DEFINE_printUImmOperand(N) \
	void CONCAT(printUImmOperand, N)(MCInst * MI, int OpNum, SStream *O) \
	{ \
		MCOperand *MO = MCInst_getOperand(MI, (OpNum)); \
		if (MCOperand_isExpr(MO)) { \
			printExpr(O, MCOperand_getExpr(MO)); \
			return; \
		} \
		uint64_t Value = (uint64_t)(MCOperand_getImm(MO)); \
		CS_ASSERT((isUIntN(N, Value) && "Invalid uimm argument")); \
		printUInt64(markup_OS(O, Markup_Immediate), Value); \
	}
DEFINE_printUImmOperand(1);
DEFINE_printUImmOperand(2);
DEFINE_printUImmOperand(3);
DEFINE_printUImmOperand(4);
DEFINE_printUImmOperand(8);
DEFINE_printUImmOperand(12);
DEFINE_printUImmOperand(16);
DEFINE_printUImmOperand(32);
DEFINE_printUImmOperand(48);

#define DEFINE_printSImmOperand(N) \
	void CONCAT(printSImmOperand, N)(MCInst * MI, int OpNum, SStream *O) \
	{ \
		MCOperand *MO = MCInst_getOperand(MI, (OpNum)); \
		if (MCOperand_isExpr(MO)) { \
			printExpr(O, MCOperand_getExpr(MO)); \
			return; \
		} \
		int64_t Value = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		if (N == 8) \
			printInt8(markup_OS(O, Markup_Immediate), Value); \
		else if (N == 16) \
			printInt16(markup_OS(O, Markup_Immediate), Value); \
		else if (N == 32) \
			printInt32(markup_OS(O, Markup_Immediate), Value); \
		else \
			CS_ASSERT(0 && "Unreachable"); \
	}
DEFINE_printSImmOperand(8);
DEFINE_printSImmOperand(16);
DEFINE_printSImmOperand(32);

static void printU1ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U1ImmOperand, OpNum);
	CONCAT(printUImmOperand, 1)(MI, OpNum, O);
}

static void printU2ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U2ImmOperand, OpNum);
	CONCAT(printUImmOperand, 2)(MI, OpNum, O);
}

static void printU3ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U3ImmOperand, OpNum);
	CONCAT(printUImmOperand, 3)(MI, OpNum, O);
}

static void printU4ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U4ImmOperand, OpNum);
	CONCAT(printUImmOperand, 4)(MI, OpNum, O);
}

static void printS8ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_S8ImmOperand, OpNum);
	CONCAT(printSImmOperand, 8)(MI, OpNum, O);
}

static void printU8ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U8ImmOperand, OpNum);
	CONCAT(printUImmOperand, 8)(MI, OpNum, O);
}

static void printU12ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U12ImmOperand, OpNum);
	CONCAT(printUImmOperand, 12)(MI, OpNum, O);
}

static void printS16ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_S16ImmOperand, OpNum);
	CONCAT(printSImmOperand, 16)(MI, OpNum, O);
}

static void printU16ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U16ImmOperand, OpNum);
	CONCAT(printUImmOperand, 16)(MI, OpNum, O);
}

static void printS32ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_S32ImmOperand, OpNum);
	CONCAT(printSImmOperand, 32)(MI, OpNum, O);
}

static void printU32ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U32ImmOperand, OpNum);
	CONCAT(printUImmOperand, 32)(MI, OpNum, O);
}

static void printU48ImmOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_U48ImmOperand, OpNum);
	CONCAT(printUImmOperand, 48)(MI, OpNum, O);
}

static void printPCRelOperand(MCInst *MI, uint64_t Address, int OpNum,
			      SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_PCRelOperand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		printInt64(O, MCOperand_getImm(MO));
	} else
		printExpr(O, MCOperand_getExpr(MO));
}

static void printPCRelTLSOperand(MCInst *MI, uint64_t Address, int OpNum,
				 SStream *O)
{
	// Output the PC-relative operand.
	printPCRelOperand(MI, MI->address, OpNum, O);

	// Output the TLS marker if present.
	if ((unsigned)OpNum + 1 < MCInst_getNumOperands(MI)) {
		// Expressions not supported
	}
}

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_Operand, OpNum);
	printMCOperand(MI, MCInst_getOperand(MI, (OpNum)), O);
}

static void printBDAddrOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_BDAddrOperand, OpNum);
	printAddress(&MI->MAI, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))),
		     MCInst_getOperand(MI, (OpNum + 1)), 0, O);
}

static void printBDXAddrOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_BDXAddrOperand, OpNum);
	printAddress(&MI->MAI, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))),
		     MCInst_getOperand(MI, (OpNum + 1)),
		     MCOperand_getReg(MCInst_getOperand(MI, (OpNum + 2))), O);
}

static void printBDLAddrOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_BDLAddrOperand, OpNum);
	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	MCOperand *DispMO = MCInst_getOperand(MI, (OpNum + 1));
	uint64_t Length = MCOperand_getImm(MCInst_getOperand(MI, (OpNum + 2)));
	printMCOperandMAI(DispMO, &MI->MAI, O);
	SStream_concat1(O, '(');
	printUInt64(O, Length);
	if (Base) {
		SStream_concat0(O, ",");
		printRegName(MI, O, Base);
	}
	SStream_concat0(O, ")");
}

static void printBDRAddrOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_BDRAddrOperand, OpNum);
	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	MCOperand *DispMO = MCInst_getOperand(MI, (OpNum + 1));
	unsigned Length = MCOperand_getReg(MCInst_getOperand(MI, (OpNum + 2)));
	printMCOperandMAI(DispMO, &MI->MAI, O);
	SStream_concat0(O, "(");
	printRegName(MI, O, Length);
	if (Base) {
		SStream_concat0(O, ",");
		printRegName(MI, O, Base);
	}
	SStream_concat0(O, ")");
}

static void printBDVAddrOperand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_BDVAddrOperand, OpNum);
	printAddress(&MI->MAI, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))),
		     MCInst_getOperand(MI, (OpNum + 1)),
		     MCOperand_getReg(MCInst_getOperand(MI, (OpNum + 2))), O);
}

static void printCond4Operand(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, SystemZ_OP_GROUP_Cond4Operand, OpNum);
	static const char *const CondNames[] = { "o",	"h",  "nle", "l",
						 "nhe", "lh", "ne",  "e",
						 "nlh", "he", "nl",  "le",
						 "nh",	"no" };
	uint64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	CS_ASSERT((Imm > 0 && Imm < 15 && "Invalid condition"));
	SStream_concat0(O, CondNames[Imm - 1]);
}

const char *SystemZ_LLVM_getRegisterName(unsigned RegNo)
{
	return getRegisterName(RegNo);
}

void SystemZ_LLVM_printInstruction(MCInst *MI, const char *Annotation,
				   SStream *O)
{
	printInst(MI, MI->address, Annotation, O);
}
