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

//===-- ARMInstPrinter.cpp - Convert ARM MCInst to assembly syntax --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an ARM MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <capstone/arm.h>

#include <capstone/platform.h>

#include "../../Mapping.h"
#include "../../MCInst.h"
#include "../../MCInstPrinter.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

#include "ARMAddressingModes.h"
#include "ARMBaseInfo.h"
#include "ARMDisassemblerExtension.h"
#include "ARMInstPrinter.h"
#include "ARMLinkage.h"
#include "ARMMapping.h"

#define GET_BANKEDREG_IMPL
#include "ARMGenSystemRegister.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

// Static function declarations. These are functions which have the same identifiers
// over all architectures. Therefor they need to be static.
#ifndef CAPSTONE_DIET
static void printCustomAliasOperand(MCInst *MI, uint64_t Address,
				    unsigned OpIdx, unsigned PrintMethodIdx,
				    SStream *O);
#endif
static const char *getRegisterName(unsigned RegNo, unsigned AltIdx);

/// translateShiftImm - Convert shift immediate from 0-31 to 1-32 for printing.
///
/// getSORegOffset returns an integer from 0-31, representing '32' as 0.
unsigned translateShiftImm(unsigned imm)
{
	// lsr #32 and asr #32 exist, but should be encoded as a 0.
	CS_ASSERT((imm & ~0x1f) == 0 && "Invalid shift encoding");

	if (imm == 0)
		return 32;
	return imm;
}

/// Prints the shift value with an immediate value.
static inline void printRegImmShift(MCInst *MI, SStream *O,
				    ARM_AM_ShiftOpc ShOpc, unsigned ShImm,
				    bool UseMarkup)
{
	add_cs_detail(MI, ARM_OP_GROUP_RegImmShift, ShOpc, ShImm);
	if (ShOpc == ARM_AM_no_shift || (ShOpc == ARM_AM_lsl && !ShImm))
		return;
	SStream_concat0(O, ", ");

	CS_ASSERT(!(ShOpc == ARM_AM_ror && !ShImm) && "Cannot have ror #0");
	SStream_concat0(O, ARM_AM_getShiftOpcStr(ShOpc));

	if (ShOpc != ARM_AM_rrx) {
		SStream_concat0(O, " ");
		if (getUseMarkup())
			SStream_concat0(O, "<imm:");
		SStream_concat(O, "%s%d", "#", translateShiftImm(ShImm));
		if (getUseMarkup())
			SStream_concat0(O, ">");
	}
}

static void printPredicateOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PredicateOperand, OpNum);
	ARMCC_CondCodes CC = (ARMCC_CondCodes)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	// Handle the undefined 15 CC value here for printing so we don't abort().
	if ((unsigned)CC == 15)
		SStream_concat0(O, "<und>");
	else if (CC != ARMCC_AL)
		SStream_concat0(O, ARMCondCodeToString(CC));
}

static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat(OS, "%s%s", markup("<reg:"),
		       getRegisterName(RegNo, ARM_NoRegAltName));
	SStream_concat0(OS, markup(">"));
}

static inline void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_Operand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op)) {
		unsigned Reg = MCOperand_getReg(Op);
		printRegName(O, Reg);
	} else if (MCOperand_isImm(Op)) {
		SStream_concat(O, "%s", markup("<imm:"));
		SStream_concat1(O, '#');
		printInt64(O, MCOperand_getImm(Op));
		SStream_concat0(O, markup(">"));
	} else {
		CS_ASSERT_RET(0 && "Expressions are not supported.");
	}
}

static inline void printRegisterList(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_RegisterList, OpNum);
	if (MCInst_getOpcode(MI) != ARM_t2CLRM) {
	}

	SStream_concat0(O, "{");
	for (unsigned i = OpNum, e = MCInst_getNumOperands(MI); i != e; ++i) {
		if (i != OpNum)
			SStream_concat0(O, ", ");
		printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (i))));
	}
	SStream_concat0(O, "}");
}

static inline void printSBitModifierOperand(MCInst *MI, unsigned OpNum,
					    SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_SBitModifierOperand, OpNum);
	if (MCOperand_getReg(MCInst_getOperand(MI, (OpNum)))) {
		SStream_concat0(O, "s");
	}
}

static inline void printOperandAddr(MCInst *MI, uint64_t Address,
				    unsigned OpNum, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	if (!MCOperand_isImm(Op) || !MI->csh->PrintBranchImmAsAddress ||
	    getUseMarkup()) {
		printOperand(MI, OpNum, O);
		return;
	}
	int64_t Imm = MCOperand_getImm(Op);
	// For ARM instructions the PC offset is 8 bytes, for Thumb instructions it
	// is 4 bytes.
	uint64_t Offset = ARM_getFeatureBits(MI->csh->mode, ARM_ModeThumb) ? 4 :
									     8;

	// A Thumb instruction BLX(i) can be 16-bit aligned while targets Arm code
	// which is 32-bit aligned. The target address for the case is calculated as
	//   targetAddress = Align(PC,4) + imm32;
	// where
	//   Align(x, y) = y * (x DIV y);
	if (MCInst_getOpcode(MI) == ARM_tBLXi)
		Address &= ~0x3;

	uint64_t Target = Address + Imm + Offset;

	Target &= 0xffffffff;
	ARM_set_detail_op_imm(MI, OpNum, ARM_OP_IMM, Target);
	printUInt64(O, Target);
}

static inline void printThumbLdrLabelOperand(MCInst *MI, unsigned OpNum,
					     SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbLdrLabelOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isExpr(MO1)) {
		// MO1.getExpr()->print(O, &MAI);
		return;
	}

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[pc, ");

	int32_t OffImm = (int32_t)MCOperand_getImm(MO1);

	// Special value for #-0. All others are normal.
	if (OffImm == INT32_MIN)
		OffImm = 0;
	SStream_concat(O, "%s", markup("<imm:"));
	printInt32Bang(O, OffImm);
	SStream_concat0(O, markup(">"));
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

// so_reg is a 4-operand unit corresponding to register forms of the A5.1
// "Addressing Mode 1 - Data-processing operands" forms.  This includes:
//    REG 0   0           - e.g. R5
//    REG REG 0,SH_OPC    - e.g. R5, ROR R3
//    REG 0   IMM,SH_OPC  - e.g. R5, LSL #3
static inline void printSORegRegOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_SORegRegOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));
	MCOperand *MO3 = MCInst_getOperand(MI, (OpNum + 2));

	printRegName(O, MCOperand_getReg(MO1));

	// Print the shift opc.
	ARM_AM_ShiftOpc ShOpc = ARM_AM_getSORegShOp(MCOperand_getImm(MO3));
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, ARM_AM_getShiftOpcStr(ShOpc));
	if (ShOpc == ARM_AM_rrx)
		return;

	SStream_concat0(O, " ");

	printRegName(O, MCOperand_getReg(MO2));
}

static inline void printSORegImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_SORegImmOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	printRegName(O, MCOperand_getReg(MO1));

	// Print the shift opc.
	printRegImmShift(MI, O, ARM_AM_getSORegShOp(MCOperand_getImm(MO2)),
			 ARM_AM_getSORegOffset(MCOperand_getImm(MO2)),
			 getUseMarkup());
}

//===--------------------------------------------------------------------===//
// Addressing Mode #2
//===--------------------------------------------------------------------===//

static inline void printAM2PreOrOffsetIndexOp(MCInst *MI, unsigned Op,
					      SStream *O)
{
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));
	MCOperand *MO3 = MCInst_getOperand(MI, (Op + 2));

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));

	if (!MCOperand_getReg(MO2)) {
		if (ARM_AM_getAM2Offset(
			    MCOperand_getImm(MO3))) { // Don't print +0.
			SStream_concat(
				O, "%s%s%s", ", ", markup("<imm:"), "#",
				ARM_AM_getAddrOpcStr(
					ARM_AM_getAM2Op(MCOperand_getImm(MO3))),
				ARM_AM_getAM2Offset(MCOperand_getImm(MO3)));
			SStream_concat0(O, markup(">"));
		}
		SStream_concat(O, "%s", "]");
		SStream_concat0(O, markup(">"));
		return;
	}

	SStream_concat0(O, ", ");
	SStream_concat0(O, ARM_AM_getAddrOpcStr(
				   ARM_AM_getAM2Op(MCOperand_getImm(MO3))));
	printRegName(O, MCOperand_getReg(MO2));

	printRegImmShift(MI, O, ARM_AM_getAM2ShiftOpc(MCOperand_getImm(MO3)),
			 ARM_AM_getAM2Offset(MCOperand_getImm(MO3)),
			 getUseMarkup());
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printAddrModeTBB(MCInst *MI, unsigned Op, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrModeTBB, Op);
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));
	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MO2));
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printAddrModeTBH(MCInst *MI, unsigned Op, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrModeTBH, Op);
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));
	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MO2));
	SStream_concat(O, "%s%s%s%s%s", ", lsl ", markup("<imm:"), "#1",
		       markup(">"), "]");
	SStream_concat0(O, markup(">"));
}

static inline void printAddrMode2Operand(MCInst *MI, unsigned Op, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode2Operand, Op);
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));

	if (!MCOperand_isReg(
		    MO1)) { // FIXME: This is for CP entries, but isn't right.
		printOperand(MI, Op, O);
		return;
	}

	printAM2PreOrOffsetIndexOp(MI, Op, O);
}

static inline void printAddrMode2OffsetOperand(MCInst *MI, unsigned OpNum,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode2OffsetOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	if (!MCOperand_getReg(MO1)) {
		unsigned ImmOffs = ARM_AM_getAM2Offset(MCOperand_getImm(MO2));
		SStream_concat(O, "%s", markup("<imm:"));
		SStream_concat1(O, '#');
		SStream_concat(O, "%s",
			       ARM_AM_getAddrOpcStr(
				       ARM_AM_getAM2Op(MCOperand_getImm(MO2))));
		printUInt32(O, ImmOffs);
		SStream_concat0(O, markup(">"));
		return;
	}

	SStream_concat0(O, ARM_AM_getAddrOpcStr(
				   ARM_AM_getAM2Op(MCOperand_getImm(MO2))));
	printRegName(O, MCOperand_getReg(MO1));

	printRegImmShift(MI, O, ARM_AM_getAM2ShiftOpc(MCOperand_getImm(MO2)),
			 ARM_AM_getAM2Offset(MCOperand_getImm(MO2)),
			 getUseMarkup());
}

//===--------------------------------------------------------------------===//
// Addressing Mode #3
//===--------------------------------------------------------------------===//

static inline void printAM3PreOrOffsetIndexOp(MCInst *MI, unsigned Op,
					      SStream *O, bool AlwaysPrintImm0)
{
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));
	MCOperand *MO3 = MCInst_getOperand(MI, (Op + 2));

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");

	printRegName(O, MCOperand_getReg(MO1));

	if (MCOperand_getReg(MO2)) {
		SStream_concat(O, "%s", ", ");
		SStream_concat0(O, ARM_AM_getAddrOpcStr(ARM_AM_getAM3Op(
					   MCOperand_getImm(MO3))));
		printRegName(O, MCOperand_getReg(MO2));
		SStream_concat1(O, ']');
		SStream_concat0(O, markup(">"));
		return;
	}

	// If the op is sub we have to print the immediate even if it is 0
	unsigned ImmOffs = ARM_AM_getAM3Offset(MCOperand_getImm(MO3));
	ARM_AM_AddrOpc op = ARM_AM_getAM3Op(MCOperand_getImm(MO3));

	if (AlwaysPrintImm0 || ImmOffs || (op == ARM_AM_sub)) {
		SStream_concat(O, "%s%s%s%s", ", ", markup("<imm:"), "#",
			       ARM_AM_getAddrOpcStr(op));
		printUInt32(O, ImmOffs);
		SStream_concat0(O, markup(">"));
	}
	SStream_concat1(O, ']');
	SStream_concat0(O, markup(">"));
}

#define DEFINE_printAddrMode3Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printAddrMode3Operand, AlwaysPrintImm0)( \
		MCInst * MI, unsigned Op, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_AddrMode3Operand, \
				     AlwaysPrintImm0), \
			      Op, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (Op)); \
		if (!MCOperand_isReg(MO1)) { \
			printOperand(MI, Op, O); \
			return; \
		} \
\
		printAM3PreOrOffsetIndexOp(MI, Op, O, AlwaysPrintImm0); \
	}
DEFINE_printAddrMode3Operand(false);
DEFINE_printAddrMode3Operand(true);

static inline void printAddrMode3OffsetOperand(MCInst *MI, unsigned OpNum,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode3OffsetOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	if (MCOperand_getReg(MO1)) {
		SStream_concat0(O, ARM_AM_getAddrOpcStr(ARM_AM_getAM3Op(
					   MCOperand_getImm(MO2))));
		printRegName(O, MCOperand_getReg(MO1));
		return;
	}

	unsigned ImmOffs = ARM_AM_getAM3Offset(MCOperand_getImm(MO2));
	SStream_concat(O, "%s", markup("<imm:"));
	SStream_concat1(O, '#');
	SStream_concat(
		O, "%s",
		ARM_AM_getAddrOpcStr(ARM_AM_getAM3Op(MCOperand_getImm(MO2))));
	printUInt32(O, ImmOffs);
	SStream_concat0(O, markup(">"));
}

static inline void printPostIdxImm8Operand(MCInst *MI, unsigned OpNum,
					   SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PostIdxImm8Operand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	unsigned Imm = MCOperand_getImm(MO);
	SStream_concat(O, "%s", markup("<imm:"));
	SStream_concat1(O, '#');
	SStream_concat(O, "%s", ((Imm & 256) ? "" : "-"));
	printUInt32(O, (Imm & 0xff));
	SStream_concat0(O, markup(">"));
}

static inline void printPostIdxRegOperand(MCInst *MI, unsigned OpNum,
					  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PostIdxRegOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	SStream_concat0(O, (MCOperand_getImm(MO2) ? "" : "-"));
	printRegName(O, MCOperand_getReg(MO1));
}

static inline void printPostIdxImm8s4Operand(MCInst *MI, unsigned OpNum,
					     SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PostIdxImm8s4Operand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	unsigned Imm = MCOperand_getImm(MO);
	SStream_concat(O, "%s", markup("<imm:"));
	SStream_concat1(O, '#');
	SStream_concat(O, "%s", ((Imm & 256) ? "" : "-"));
	printUInt32(O, (Imm & 0xff) << 2);
	SStream_concat0(O, markup(">"));
}

#define DEFINE_printMveAddrModeRQOperand(shift) \
	static inline void CONCAT(printMveAddrModeRQOperand, shift)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail( \
			MI, CONCAT(ARM_OP_GROUP_MveAddrModeRQOperand, shift), \
			OpNum, shift); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
		SStream_concat0(O, ", "); \
		printRegName(O, MCOperand_getReg(MO2)); \
\
		if (shift > 0) \
			printRegImmShift(MI, O, ARM_AM_uxtw, shift, \
					 getUseMarkup()); \
\
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printMveAddrModeRQOperand(0);
DEFINE_printMveAddrModeRQOperand(3);
DEFINE_printMveAddrModeRQOperand(1);
DEFINE_printMveAddrModeRQOperand(2);

#define DEFINE_printAddrMode5Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printAddrMode5Operand, AlwaysPrintImm0)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_AddrMode5Operand, \
				     AlwaysPrintImm0), \
			      OpNum, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
\
		unsigned ImmOffs = ARM_AM_getAM5Offset(MCOperand_getImm(MO2)); \
		ARM_AM_AddrOpc Op = ARM_AM_getAM5Op(MCOperand_getImm(MO2)); \
		if (AlwaysPrintImm0 || ImmOffs || Op == ARM_AM_sub) { \
			SStream_concat(O, "%s%s%s%s", ", ", markup("<imm:"), \
				       "#", ARM_AM_getAddrOpcStr(Op)); \
			printUInt32(O, ImmOffs * 4); \
			SStream_concat0(O, markup(">")); \
		} \
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printAddrMode5Operand(false);
DEFINE_printAddrMode5Operand(true);

#define DEFINE_printAddrMode5FP16Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printAddrMode5FP16Operand, AlwaysPrintImm0)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_AddrMode5FP16Operand, \
				     AlwaysPrintImm0), \
			      OpNum, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		if (!MCOperand_isReg(MO1)) { \
			printOperand(MI, OpNum, O); \
			return; \
		} \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
\
		unsigned ImmOffs = \
			ARM_AM_getAM5FP16Offset(MCOperand_getImm(MO2)); \
		unsigned Op = ARM_AM_getAM5FP16Op(MCOperand_getImm(MO2)); \
		if (AlwaysPrintImm0 || ImmOffs || Op == ARM_AM_sub) { \
			SStream_concat( \
				O, "%s%s%s%s", ", ", markup("<imm:"), "#", \
				ARM_AM_getAddrOpcStr(ARM_AM_getAM5FP16Op( \
					MCOperand_getImm(MO2)))); \
			printUInt32(O, ImmOffs * 2); \
			SStream_concat0(O, markup(">")); \
		} \
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printAddrMode5FP16Operand(false);

static inline void printAddrMode6Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode6Operand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	if (MCOperand_getImm(MO2)) {
		SStream_concat(O, "%s", ":");
		printInt64(O, ((uint32_t)MCOperand_getImm(MO2)) << 3);
	}
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printAddrMode7Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode7Operand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printAddrMode6OffsetOperand(MCInst *MI, unsigned OpNum,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_AddrMode6OffsetOperand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_getReg(MO) == 0)
		SStream_concat0(O, "!");
	else {
		SStream_concat0(O, ", ");
		printRegName(O, MCOperand_getReg(MO));
	}
}

static inline void printBitfieldInvMaskImmOperand(MCInst *MI, unsigned OpNum,
						  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_BitfieldInvMaskImmOperand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	uint32_t v = ~MCOperand_getImm(MO);
	int32_t lsb = CountTrailingZeros_32(v);
	int32_t width = (32 - countLeadingZeros(v)) - lsb;

	SStream_concat(O, "%s", markup("<imm:"));
	SStream_concat1(O, '#');
	printInt32(O, lsb);
	SStream_concat(O, "%s%s%s", markup(">"), ", ", markup("<imm:"));
	printInt32Bang(O, width);
	SStream_concat0(O, markup(">"));
}

static inline void printMemBOption(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MemBOption, OpNum);
	unsigned val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, ARM_MB_MemBOptToString(
				   val, ARM_getFeatureBits(MI->csh->mode,
							   ARM_HasV8Ops)));
}

static inline void printInstSyncBOption(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_InstSyncBOption, OpNum);
	unsigned val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, ARM_ISB_InstSyncBOptToString(val));
}

static inline void printTraceSyncBOption(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_TraceSyncBOption, OpNum);
	unsigned val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, ARM_TSB_TraceSyncBOptToString(val));
}

static inline void printShiftImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ShiftImmOperand, OpNum);
	unsigned ShiftOp = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	bool isASR = (ShiftOp & (1 << 5)) != 0;
	unsigned Amt = ShiftOp & 0x1f;
	if (isASR) {
		SStream_concat(O, "%s%s%s", ", asr ", markup("<imm:"), "#");
		printUInt32(O, Amt == 0 ? 32 : Amt);
		SStream_concat0(O, markup(">"));
	} else if (Amt) {
		SStream_concat(O, "%s%s%s", ", lsl ", markup("<imm:"), "#");
		printUInt32(O, Amt);
		SStream_concat0(O, markup(">"));
	}
}

static inline void printPKHLSLShiftImm(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PKHLSLShiftImm, OpNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	if (Imm == 0)
		return;

	SStream_concat(O, "%s%s%s", ", lsl ", markup("<imm:"), "#");
	printUInt32(O, Imm);
	SStream_concat0(O, markup(">"));
}

static inline void printPKHASRShiftImm(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PKHASRShiftImm, OpNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	// A shift amount of 32 is encoded as 0.
	if (Imm == 0)
		Imm = 32;

	SStream_concat(O, "%s%s%s", ", asr ", markup("<imm:"), "#");
	printUInt32(O, Imm);
	SStream_concat0(O, markup(">"));
}

static inline void printGPRPairOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_GPRPairOperand, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	printRegName(O, MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_gsub_0));
	SStream_concat0(O, ", ");
	printRegName(O, MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_gsub_1));
}

static inline void printSetendOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_SetendOperand, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_getImm(Op))
		SStream_concat0(O, "be");
	else
		SStream_concat0(O, "le");
}

static inline void printCPSIMod(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_CPSIMod, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	SStream_concat0(O, ARM_PROC_IModToString(MCOperand_getImm(Op)));
}

static inline void printCPSIFlag(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_CPSIFlag, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));
	unsigned IFlags = MCOperand_getImm(Op);
	for (int i = 2; i >= 0; --i)
		if (IFlags & (1 << i))
			SStream_concat0(O, ARM_PROC_IFlagsToString(1 << i));

	if (IFlags == 0)
		SStream_concat0(O, "none");
}

static inline void printMSRMaskOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MSRMaskOperand, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	if (ARM_getFeatureBits(MI->csh->mode, ARM_FeatureMClass)) {
		unsigned SYSm = MCOperand_getImm(Op) & 0xFFF; // 12-bit SYSm
		unsigned Opcode = MCInst_getOpcode(MI);

		// For writes, handle extended mask bits if the DSP extension is
		// present.
		if (Opcode == ARM_t2MSR_M &&
		    ARM_getFeatureBits(MI->csh->mode, ARM_FeatureDSP)) {
			const ARMSysReg_MClassSysReg *TheReg =
				ARMSysReg_lookupMClassSysRegBy12bitSYSmValue(
					SYSm);
			if (TheReg && MClassSysReg_isInRequiredFeatures(
					      TheReg, ARM_FeatureDSP)) {
				SStream_concat0(O, TheReg->Name);
				return;
			}
		}

		// Handle the basic 8-bit mask.
		SYSm &= 0xff;
		if (Opcode == ARM_t2MSR_M &&
		    ARM_getFeatureBits(MI->csh->mode, ARM_HasV7Ops)) {
			// ARMv7-M deprecates using MSR APSR without a _<bits> qualifier as
			// an alias for MSR APSR_nzcvq.
			const ARMSysReg_MClassSysReg *TheReg =
				ARMSysReg_lookupMClassSysRegAPSRNonDeprecated(
					SYSm);
			if (TheReg) {
				SStream_concat0(O, TheReg->Name);
				return;
			}
		}

		const ARMSysReg_MClassSysReg *TheReg =
			ARMSysReg_lookupMClassSysRegBy8bitSYSmValue(SYSm);
		if (TheReg) {
			SStream_concat0(O, TheReg->Name);
			return;
		}

		printUInt32(O, SYSm);

		return;
	}

	// As special cases, CPSR_f, CPSR_s and CPSR_fs prefer printing as
	// APSR_nzcvq, APSR_g and APSRnzcvqg, respectively.
	unsigned SpecRegRBit = MCOperand_getImm(Op) >> 4;
	unsigned Mask = MCOperand_getImm(Op) & 0xf;

	if (!SpecRegRBit && (Mask == 8 || Mask == 4 || Mask == 12)) {
		SStream_concat0(O, "apsr_");
		switch (Mask) {
		default:
			CS_ASSERT_RET(0 && "Unexpected mask value!");
		case 4:
			SStream_concat0(O, "g");
			return;
		case 8:
			SStream_concat0(O, "nzcvq");
			return;
		case 12:
			SStream_concat0(O, "nzcvqg");
			return;
		}
	}

	if (SpecRegRBit)
		SStream_concat0(O, "spsr");
	else
		SStream_concat0(O, "cpsr");

	if (Mask) {
		SStream_concat0(O, "_");

		if (Mask & 8)
			SStream_concat0(O, "f");

		if (Mask & 4)
			SStream_concat0(O, "s");

		if (Mask & 2)
			SStream_concat0(O, "x");

		if (Mask & 1)
			SStream_concat0(O, "c");
	}
}

static inline void printBankedRegOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_BankedRegOperand, OpNum);
	uint32_t Banked = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	const ARMBankedReg_BankedReg *TheReg =
		ARMBankedReg_lookupBankedRegByEncoding(Banked);

	const char *Name = TheReg->Name;

	// uint32_t isSPSR = (Banked & 0x20) >> 5;
	// if (isSPSR)
	// 	Name.replace(0, 4, "SPSR"); // convert 'spsr_' to 'SPSR_'
	SStream_concat0(O, Name);
}

static inline void printMandatoryPredicateOperand(MCInst *MI, unsigned OpNum,
						  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MandatoryPredicateOperand, OpNum);
	ARMCC_CondCodes CC = (ARMCC_CondCodes)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, ARMCondCodeToString(CC));
}

static inline void
printMandatoryRestrictedPredicateOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MandatoryRestrictedPredicateOperand,
		      OpNum);
	if ((ARMCC_CondCodes)MCOperand_getImm(MCInst_getOperand(MI, (OpNum))) ==
	    ARMCC_HS)
		SStream_concat0(O, "cs");
	else
		printMandatoryPredicateOperand(MI, OpNum, O);
}

static inline void
printMandatoryInvertedPredicateOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MandatoryInvertedPredicateOperand,
		      OpNum);
	ARMCC_CondCodes CC = (ARMCC_CondCodes)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, ARMCondCodeToString(ARMCC_getOppositeCondition(CC)));
}

static inline void printNoHashImmediate(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_NoHashImmediate, OpNum);
	printInt64(O, MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
}

static inline void printPImmediate(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_PImmediate, OpNum);
	SStream_concat(O, "%s%d", "p",
		       MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
}

static inline void printCImmediate(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_CImmediate, OpNum);
	SStream_concat(O, "%s%d", "c",
		       MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
}

static inline void printCoprocOptionImm(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_CoprocOptionImm, OpNum);
	SStream_concat(O, "%s", "{");
	printInt64(O, MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "}");
}

#define DEFINE_printAdrLabelOperand(scale) \
	static inline void CONCAT(printAdrLabelOperand, scale)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, CONCAT(ARM_OP_GROUP_AdrLabelOperand, scale), \
			      OpNum, scale); \
		MCOperand *MO = MCInst_getOperand(MI, (OpNum)); \
\
		if (MCOperand_isExpr(MO)) { \
			return; \
		} \
\
		int32_t OffImm = (uint32_t)MCOperand_getImm(MO) << scale; \
\
		SStream_concat0(O, markup("<imm:")); \
		if (OffImm == INT32_MIN) \
			SStream_concat0(O, "#-0"); \
		else if (OffImm < 0) { \
			printInt32Bang(O, OffImm); \
		} else { \
			printInt32Bang(O, OffImm); \
		} \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printAdrLabelOperand(0);
DEFINE_printAdrLabelOperand(2);

#define DEFINE_printAdrLabelOperandAddr(scale) \
	static inline void CONCAT(printAdrLabelOperandAddr, scale)( \
		MCInst * MI, uint64_t Address, unsigned OpNum, SStream *O) \
	{ \
		CONCAT(printAdrLabelOperand, scale)(MI, OpNum, O); \
	}
DEFINE_printAdrLabelOperandAddr(2);

static inline void printThumbS4ImmOperand(MCInst *MI, unsigned OpNum,
					  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbS4ImmOperand, OpNum);
	SStream_concat(O, "%s", markup("<imm:"));
	printInt64Bang(O, MCOperand_getImm(MCInst_getOperand(MI, (OpNum))) * 4);
	SStream_concat0(O, markup(">"));
}

static inline void printThumbSRImm(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbSRImm, OpNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	SStream_concat(O, "%s", markup("<imm:"));
	printUInt32Bang(O, (Imm == 0 ? 32 : Imm));
	SStream_concat0(O, markup(">"));
}

static inline void printThumbITMask(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbITMask, OpNum);
	// (3 - the number of trailing zeros) is the number of then / else.
	unsigned Mask = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	unsigned NumTZ = CountTrailingZeros_32(Mask);

	for (unsigned Pos = 3, e = NumTZ; Pos > e; --Pos) {
		if ((Mask >> Pos) & 1)
			SStream_concat0(O, "e");

		else
			SStream_concat0(O, "t");
	}
}

static inline void printThumbAddrModeRROperand(MCInst *MI, unsigned Op,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbAddrModeRROperand, Op);
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));

	if (!MCOperand_isReg(
		    MO1)) { // FIXME: This is for CP entries, but isn't right.
		printOperand(MI, Op, O);
		return;
	}

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	unsigned RegNum = MCOperand_getReg(MO2);
	if (RegNum) {
		SStream_concat0(O, ", ");
		printRegName(O, RegNum);
	}
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printThumbAddrModeImm5SOperand(MCInst *MI, unsigned Op,
						  SStream *O, unsigned Scale)
{
	MCOperand *MO1 = MCInst_getOperand(MI, (Op));
	MCOperand *MO2 = MCInst_getOperand(MI, (Op + 1));

	if (!MCOperand_isReg(
		    MO1)) { // FIXME: This is for CP entries, but isn't right.
		printOperand(MI, Op, O);
		return;
	}

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	unsigned ImmOffs = MCOperand_getImm(MO2);
	if (ImmOffs) {
		SStream_concat(O, "%s%s", ", ", markup("<imm:"));
		printUInt32Bang(O, ImmOffs * Scale);
		SStream_concat0(O, markup(">"));
	}
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printThumbAddrModeImm5S1Operand(MCInst *MI, unsigned Op,
						   SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbAddrModeImm5S1Operand, Op);
	printThumbAddrModeImm5SOperand(MI, Op, O, 1);
}

static inline void printThumbAddrModeImm5S2Operand(MCInst *MI, unsigned Op,
						   SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbAddrModeImm5S2Operand, Op);
	printThumbAddrModeImm5SOperand(MI, Op, O, 2);
}

static inline void printThumbAddrModeImm5S4Operand(MCInst *MI, unsigned Op,
						   SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbAddrModeImm5S4Operand, Op);
	printThumbAddrModeImm5SOperand(MI, Op, O, 4);
}

static inline void printThumbAddrModeSPOperand(MCInst *MI, unsigned Op,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ThumbAddrModeSPOperand, Op);
	printThumbAddrModeImm5SOperand(MI, Op, O, 4);
}

// Constant shifts t2_so_reg is a 2-operand unit corresponding to the Thumb2
// register with shift forms.
// REG 0   0           - e.g. R5
// REG IMM, SH_OPC     - e.g. R5, LSL #3
static inline void printT2SOOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_T2SOOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	unsigned Reg = MCOperand_getReg(MO1);
	printRegName(O, Reg);

	// Print the shift opc.

	printRegImmShift(MI, O, ARM_AM_getSORegShOp(MCOperand_getImm(MO2)),
			 ARM_AM_getSORegOffset(MCOperand_getImm(MO2)),
			 getUseMarkup());
}

#define DEFINE_printAddrModeImm12Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printAddrModeImm12Operand, AlwaysPrintImm0)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_AddrModeImm12Operand, \
				     AlwaysPrintImm0), \
			      OpNum, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		if (!MCOperand_isReg(MO1)) { \
			printOperand(MI, OpNum, O); \
			return; \
		} \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
\
		int32_t OffImm = (int32_t)MCOperand_getImm(MO2); \
		bool isSub = OffImm < 0; \
\
		if (OffImm == INT32_MIN) \
			OffImm = 0; \
		if (isSub) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} else if (AlwaysPrintImm0 || OffImm > 0) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} \
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printAddrModeImm12Operand(false);
DEFINE_printAddrModeImm12Operand(true);

#define DEFINE_printT2AddrModeImm8Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printT2AddrModeImm8Operand, \
				  AlwaysPrintImm0)(MCInst * MI, \
						   unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_T2AddrModeImm8Operand, \
				     AlwaysPrintImm0), \
			      OpNum, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
\
		int32_t OffImm = (int32_t)MCOperand_getImm(MO2); \
		bool isSub = OffImm < 0; \
\
		if (OffImm == INT32_MIN) \
			OffImm = 0; \
		if (isSub) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} else if (AlwaysPrintImm0 || OffImm > 0) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} \
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printT2AddrModeImm8Operand(true);
DEFINE_printT2AddrModeImm8Operand(false);

#define DEFINE_printT2AddrModeImm8s4Operand(AlwaysPrintImm0) \
	static inline void CONCAT(printT2AddrModeImm8s4Operand, \
				  AlwaysPrintImm0)(MCInst * MI, \
						   unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(ARM_OP_GROUP_T2AddrModeImm8s4Operand, \
				     AlwaysPrintImm0), \
			      OpNum, AlwaysPrintImm0); \
		MCOperand *MO1 = MCInst_getOperand(MI, (OpNum)); \
		MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1)); \
\
		if (!MCOperand_isReg(MO1)) { \
			printOperand(MI, OpNum, O); \
			return; \
		} \
\
		SStream_concat(O, "%s", markup("<mem:")); \
		SStream_concat0(O, "["); \
		printRegName(O, MCOperand_getReg(MO1)); \
\
		int32_t OffImm = (int32_t)MCOperand_getImm(MO2); \
		bool isSub = OffImm < 0; \
\
		if (OffImm == INT32_MIN) \
			OffImm = 0; \
		if (isSub) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} else if (AlwaysPrintImm0 || OffImm > 0) { \
			SStream_concat(O, "%s%s", ", ", markup("<imm:")); \
			printInt32Bang(O, OffImm); \
			SStream_concat0(O, markup(">")); \
		} \
		SStream_concat(O, "%s", "]"); \
		SStream_concat0(O, markup(">")); \
	}

DEFINE_printT2AddrModeImm8s4Operand(false);
DEFINE_printT2AddrModeImm8s4Operand(true);

static inline void printT2AddrModeImm0_1020s4Operand(MCInst *MI, unsigned OpNum,
						     SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_T2AddrModeImm0_1020s4Operand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));
	if (MCOperand_getImm(MO2)) {
		SStream_concat(O, "%s%s", ", ", markup("<imm:"));
		printInt64Bang(O, (int32_t)(MCOperand_getImm(MO2) * 4));
		SStream_concat0(O, markup(">"));
	}
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printT2AddrModeImm8OffsetOperand(MCInst *MI, unsigned OpNum,
						    SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_T2AddrModeImm8OffsetOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	int32_t OffImm = (int32_t)MCOperand_getImm(MO1);
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, markup("<imm:"));
	if (OffImm == INT32_MIN)
		SStream_concat0(O, "#-0");
	else if (OffImm < 0) {
		printInt32Bang(O, OffImm);
	} else {
		printInt32Bang(O, OffImm);
	}
	SStream_concat0(O, markup(">"));
}

static inline void
printT2AddrModeImm8s4OffsetOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_T2AddrModeImm8s4OffsetOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	int32_t OffImm = (int32_t)MCOperand_getImm(MO1);

	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, markup("<imm:"));
	if (OffImm == INT32_MIN)
		SStream_concat0(O, "#-0");
	else if (OffImm < 0) {
		printInt32Bang(O, OffImm);
	} else {
		printInt32Bang(O, OffImm);
	}
	SStream_concat0(O, markup(">"));
}

static inline void printT2AddrModeSoRegOperand(MCInst *MI, unsigned OpNum,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_T2AddrModeSoRegOperand, OpNum);
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum));
	MCOperand *MO2 = MCInst_getOperand(MI, (OpNum + 1));
	MCOperand *MO3 = MCInst_getOperand(MI, (OpNum + 2));

	SStream_concat(O, "%s", markup("<mem:"));
	SStream_concat0(O, "[");
	printRegName(O, MCOperand_getReg(MO1));

	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MO2));

	unsigned ShAmt = MCOperand_getImm(MO3);
	if (ShAmt) {
		SStream_concat(O, "%s%s%s", ", lsl ", markup("<imm:"), "#");
		printUInt32(O, ShAmt);
		SStream_concat0(O, markup(">"));
	}
	SStream_concat(O, "%s", "]");
	SStream_concat0(O, markup(">"));
}

static inline void printFPImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_FPImmOperand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	SStream_concat(O, "%s", markup("<imm:"));
	printFloatBang(O, ARM_AM_getFPImmFloat(MCOperand_getImm(MO)));
	SStream_concat0(O, markup(">"));
}

static inline void printVMOVModImmOperand(MCInst *MI, unsigned OpNum,
					  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VMOVModImmOperand, OpNum);
	unsigned EncodedImm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	unsigned EltBits;
	uint64_t Val = ARM_AM_decodeVMOVModImm(EncodedImm, &EltBits);
	SStream_concat(O, "%s", markup("<imm:"));
	printUInt64Bang(O, Val);
	SStream_concat0(O, markup(">"));
}

static inline void printImmPlusOneOperand(MCInst *MI, unsigned OpNum,
					  SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ImmPlusOneOperand, OpNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	SStream_concat(O, "%s", markup("<imm:"));
	printUInt32Bang(O, Imm + 1);
	SStream_concat0(O, markup(">"));
}

static inline void printRotImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_RotImmOperand, OpNum);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	if (Imm == 0)
		return;

	SStream_concat(O, "%s%s%s%d", ", ror ", markup("<imm:"), "#", 8 * Imm);
	SStream_concat0(O, markup(">"));
}

static inline void printModImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_ModImmOperand, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	// Support for fixups (MCFixup)
	if (MCOperand_isExpr(Op)) {
		printOperand(MI, OpNum, O);
		return;
	}

	unsigned Bits = MCOperand_getImm(Op) & 0xFF;
	unsigned Rot = (MCOperand_getImm(Op) & 0xF00) >> 7;

	bool PrintUnsigned = false;
	switch (MCInst_getOpcode(MI)) {
	case ARM_MOVi:
		// Movs to PC should be treated unsigned
		PrintUnsigned =
			(MCOperand_getReg(MCInst_getOperand(MI, (OpNum - 1))) ==
			 ARM_PC);
		break;
	case ARM_MSRi:
		// Movs to special registers should be treated unsigned
		PrintUnsigned = true;
		break;
	}

	int32_t Rotated = ARM_AM_rotr32(Bits, Rot);
	if (ARM_AM_getSOImmVal(Rotated) == MCOperand_getImm(Op)) {
		// #rot has the least possible value
		SStream_concat(O, "%s", "#");
		SStream_concat0(O, markup("<imm:"));
		if (PrintUnsigned)
			printUInt32(O, (uint32_t)(Rotated));
		else
			printInt32(O, Rotated);
		SStream_concat0(O, markup(">"));
		return;
	}

	// Explicit #bits, #rot implied
	SStream_concat(O, "%s%s%u", "#", markup("<imm:"), Bits);
	SStream_concat(O, "%s%s%s%u", markup(">"), ", #", markup("<imm:"), Rot);
	SStream_concat0(O, markup(">"));
}

static inline void printFBits16(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_FBits16, OpNum);
	SStream_concat(O, "%s%s", markup("<imm:"), "#");
	SStream_concat(O, "%d",
		       16 - MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, markup(">"));
}

static inline void printFBits32(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_FBits32, OpNum);
	SStream_concat(O, "%s%s", markup("<imm:"), "#");
	printInt64(O, 32 - MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, markup(">"));
}

static inline void printVectorIndex(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorIndex, OpNum);
	SStream_concat(O, "%s", "[");
	printInt64(O,
		   (int32_t)MCOperand_getImm(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "]");
}

static inline void printVectorListOne(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListOne, OpNum);
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "}");
}

static inline void printVectorListTwo(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListTwo, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	unsigned Reg0 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_0);
	unsigned Reg1 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_1);
	SStream_concat0(O, "{");
	printRegName(O, Reg0);
	SStream_concat0(O, ", ");
	printRegName(O, Reg1);
	SStream_concat0(O, "}");
}

static inline void printVectorListTwoSpaced(MCInst *MI, unsigned OpNum,
					    SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListTwoSpaced, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	unsigned Reg0 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_0);
	unsigned Reg1 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_2);
	SStream_concat0(O, "{");
	printRegName(O, Reg0);
	SStream_concat0(O, ", ");
	printRegName(O, Reg1);
	SStream_concat0(O, "}");
}

static inline void printVectorListThree(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListThree, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 1);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, "}");
}

static inline void printVectorListFour(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListFour, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 1);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 3);
	SStream_concat0(O, "}");
}

static inline void printVectorListOneAllLanes(MCInst *MI, unsigned OpNum,
					      SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListOneAllLanes, OpNum);
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "[]}");
}

static inline void printVectorListTwoAllLanes(MCInst *MI, unsigned OpNum,
					      SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListTwoAllLanes, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	unsigned Reg0 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_0);
	unsigned Reg1 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_1);
	SStream_concat0(O, "{");
	printRegName(O, Reg0);
	SStream_concat0(O, "[], ");
	printRegName(O, Reg1);
	SStream_concat0(O, "[]}");
}

static inline void printVectorListThreeAllLanes(MCInst *MI, unsigned OpNum,
						SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListThreeAllLanes, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 1);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, "[]}");
}

static inline void printVectorListFourAllLanes(MCInst *MI, unsigned OpNum,
					       SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListFourAllLanes, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 1);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 3);
	SStream_concat0(O, "[]}");
}

static inline void printVectorListTwoSpacedAllLanes(MCInst *MI, unsigned OpNum,
						    SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListTwoSpacedAllLanes, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	unsigned Reg0 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_0);
	unsigned Reg1 = MCRegisterInfo_getSubReg(MI->MRI, Reg, ARM_dsub_2);
	SStream_concat0(O, "{");
	printRegName(O, Reg0);
	SStream_concat0(O, "[], ");
	printRegName(O, Reg1);
	SStream_concat0(O, "[]}");
}

static inline void
printVectorListThreeSpacedAllLanes(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListThreeSpacedAllLanes, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 4);
	SStream_concat0(O, "[]}");
}

static inline void printVectorListFourSpacedAllLanes(MCInst *MI, unsigned OpNum,
						     SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListFourSpacedAllLanes, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 4);
	SStream_concat0(O, "[], ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 6);
	SStream_concat0(O, "[]}");
}

static inline void printVectorListThreeSpaced(MCInst *MI, unsigned OpNum,
					      SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListThreeSpaced, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 4);
	SStream_concat0(O, "}");
}

static inline void printVectorListFourSpaced(MCInst *MI, unsigned OpNum,
					     SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VectorListFourSpaced, OpNum);
	// Normally, it's not safe to use register enum values directly with
	// addition to get the next register, but for VFP registers, the
	// sort order is guaranteed because they're all of the form D<n>.
	SStream_concat0(O, "{");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 2);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 4);
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))) + 6);
	SStream_concat0(O, "}");
}

#define DEFINE_printMVEVectorList(NumRegs) \
	static inline void CONCAT(printMVEVectorList, NumRegs)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, CONCAT(ARM_OP_GROUP_MVEVectorList, NumRegs), \
			      OpNum, NumRegs); \
		unsigned Reg = \
			MCOperand_getReg(MCInst_getOperand(MI, (OpNum))); \
		const char *Prefix = "{"; \
		for (unsigned i = 0; i < NumRegs; i++) { \
			SStream_concat0(O, Prefix); \
			printRegName( \
				O, MCRegisterInfo_getSubReg(MI->MRI, Reg, \
							    ARM_qsub_0 + i)); \
			Prefix = ", "; \
		} \
		SStream_concat0(O, "}"); \
	}
DEFINE_printMVEVectorList(2) DEFINE_printMVEVectorList(4)

#define DEFINE_printComplexRotationOp(Angle, Remainder) \
	static inline void CONCAT(printComplexRotationOp, \
				  CONCAT(Angle, Remainder))( \
		MCInst * MI, unsigned OpNo, SStream *O) \
	{ \
		add_cs_detail( \
			MI, \
			CONCAT(CONCAT(ARM_OP_GROUP_ComplexRotationOp, Angle), \
			       Remainder), \
			OpNo, Angle, Remainder); \
		unsigned Val = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNo))); \
		SStream_concat(O, "#%d", (Val * Angle) + Remainder); \
	}
	DEFINE_printComplexRotationOp(90, 0) DEFINE_printComplexRotationOp(180,
									   90)

		static inline void printVPTPredicateOperand(MCInst *MI,
							    unsigned OpNum,
							    SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VPTPredicateOperand, OpNum);
	ARMVCC_VPTCodes CC = (ARMVCC_VPTCodes)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	if (CC != ARMVCC_None)
		SStream_concat0(O, ARMVPTPredToString(CC));
}

static inline void printVPTMask(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_VPTMask, OpNum);
	// (3 - the number of trailing zeroes) is the number of them / else.
	unsigned Mask = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	unsigned NumTZ = CountTrailingZeros_32(Mask);

	for (unsigned Pos = 3, e = NumTZ; Pos > e; --Pos) {
		bool T = ((Mask >> Pos) & 1) == 0;
		if (T)
			SStream_concat0(O, "t");

		else
			SStream_concat0(O, "e");
	}
}

static inline void printMveSaturateOp(MCInst *MI, unsigned OpNum, SStream *O)
{
	add_cs_detail(MI, ARM_OP_GROUP_MveSaturateOp, OpNum);
	uint32_t Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

	printUInt32Bang(O, (Val == 1 ? 48 : 64));
}

#define PRINT_ALIAS_INSTR
#include "ARMGenAsmWriter.inc"

static void printInst(MCInst *MI, SStream *O, void *info)
{
	bool isAlias = false;
	bool useAliasDetails = map_use_alias_details(MI);
	map_set_fill_detail_ops(MI, useAliasDetails);
	unsigned Opcode = MCInst_getOpcode(MI);
	uint64_t Address = MI->address;

	switch (Opcode) {
	// Check for MOVs and print canonical forms, instead.
	case ARM_MOVsr: {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		// FIXME: Thumb variants?
		MCOperand *MO3 = MCInst_getOperand(MI, (3));

		SStream_concat1(O, ' ');
		SStream_concat0(O, ARM_AM_getShiftOpcStr(ARM_AM_getSORegShOp(
					   MCOperand_getImm(MO3))));
		printSBitModifierOperand(MI, 6, O);
		printPredicateOperand(MI, 4, O);

		SStream_concat0(O, " ");

		printOperand(MI, 0, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 1, O);

		SStream_concat0(O, ", ");
		printOperand(MI, 2, O);

		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	}

	case ARM_MOVsi: {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		// FIXME: Thumb variants?
		MCOperand *MO2 = MCInst_getOperand(MI, (2));

		SStream_concat0(O, ARM_AM_getShiftOpcStr(ARM_AM_getSORegShOp(
					   MCOperand_getImm(MO2))));
		printSBitModifierOperand(MI, 5, O);
		printPredicateOperand(MI, 3, O);

		SStream_concat0(O, " ");

		printOperand(MI, 0, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 1, O);

		if (ARM_AM_getSORegShOp(MCOperand_getImm(MO2)) == ARM_AM_rrx) {
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		}

		SStream_concat(O, "%s%s%s%d", ", ", markup("<imm:"), "#",
			       translateShiftImm(ARM_AM_getSORegOffset(
				       MCOperand_getImm(MO2))));
		SStream_concat0(O, markup(">"));
		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	}

	// A8.6.123 PUSH
	case ARM_STMDB_UPD:
	case ARM_t2STMDB_UPD:
		if (MCOperand_getReg(MCInst_getOperand(MI, (0))) == ARM_SP &&
		    MCInst_getNumOperands(MI) > 5) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			// Should only print PUSH if there are at least two registers in the
			// list.
			SStream_concat0(O, "push");
			printPredicateOperand(MI, 2, O);
			if (Opcode == ARM_t2STMDB_UPD)
				SStream_concat0(O, ".w");
			SStream_concat0(O, " ");

			printRegisterList(MI, 4, O);
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	case ARM_STR_PRE_IMM:
		if (MCOperand_getReg(MCInst_getOperand(MI, (2))) == ARM_SP &&
		    MCOperand_getImm(MCInst_getOperand(MI, (3))) == -4) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat1(O, ' ');
			SStream_concat0(O, "push");
			printPredicateOperand(MI, 4, O);
			SStream_concat0(O, " {");
			printOperand(MI, 1, O);
			SStream_concat0(O, "}");
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	// A8.6.122 POP
	case ARM_LDMIA_UPD:
	case ARM_t2LDMIA_UPD:
		if (MCOperand_getReg(MCInst_getOperand(MI, (0))) == ARM_SP &&
		    MCInst_getNumOperands(MI) > 5) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			// Should only print POP if there are at least two registers in the
			// list.
			SStream_concat0(O, "pop");
			printPredicateOperand(MI, 2, O);
			if (Opcode == ARM_t2LDMIA_UPD)
				SStream_concat0(O, ".w");
			SStream_concat0(O, " ");

			printRegisterList(MI, 4, O);
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	case ARM_LDR_POST_IMM:
		if ((MCOperand_getReg(MCInst_getOperand(MI, (2))) == ARM_SP) &&
		    ((ARM_AM_getAM2Offset(MCOperand_getImm(
			      MCInst_getOperand(MI, (4)))) == 4))) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "pop");
			printPredicateOperand(MI, 5, O);
			SStream_concat0(O, " {");
			printOperand(MI, 0, O);
			SStream_concat0(O, "}");
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;
	case ARM_t2LDR_POST:
		if ((MCOperand_getReg(MCInst_getOperand(MI, (2))) == ARM_SP) &&
		    (Opcode == ARM_t2LDR_POST &&
		     (MCOperand_getImm(MCInst_getOperand(MI, (3))) == 4))) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "pop");
			printPredicateOperand(MI, 4, O);
			SStream_concat0(O, " {");
			printOperand(MI, 0, O);
			SStream_concat0(O, "}");
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	// A8.6.355 VPUSH
	case ARM_VSTMSDB_UPD:
	case ARM_VSTMDDB_UPD:
		if (MCOperand_getReg(MCInst_getOperand(MI, (0))) == ARM_SP) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "vpush");
			printPredicateOperand(MI, 2, O);
			SStream_concat0(O, " ");

			printRegisterList(MI, 4, O);
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	// A8.6.354 VPOP
	case ARM_VLDMSIA_UPD:
	case ARM_VLDMDIA_UPD:
		if (MCOperand_getReg(MCInst_getOperand(MI, (0))) == ARM_SP) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat1(O, ' ');
			SStream_concat0(O, "vpop");
			printPredicateOperand(MI, 2, O);
			SStream_concat0(O, " ");

			printRegisterList(MI, 4, O);
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else
			break;

	case ARM_tLDMIA: {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		bool Writeback = true;
		unsigned BaseReg = MCOperand_getReg(MCInst_getOperand(MI, (0)));
		for (unsigned i = 3; i < MCInst_getNumOperands(MI); ++i) {
			if (MCOperand_getReg(MCInst_getOperand(MI, (i))) ==
			    BaseReg)
				Writeback = false;
		}

		SStream_concat0(O, "ldm");

		printPredicateOperand(MI, 1, O);
		SStream_concat0(O, " ");

		printOperand(MI, 0, O);
		if (Writeback) {
			SStream_concat0(O, "!");
		}
		SStream_concat0(O, ", ");
		printRegisterList(MI, 3, O);
		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	}

	// Combine 2 GPRs from disassember into a GPRPair to match with instr def.
	// ldrexd/strexd require even/odd GPR pair. To enforce this constraint,
	// a single GPRPair reg operand is used in the .td file to replace the two
	// GPRs. However, when decoding them, the two GRPs cannot be automatically
	// expressed as a GPRPair, so we have to manually merge them.
	// FIXME: We would really like to be able to tablegen'erate this.
	case ARM_LDREXD:
	case ARM_STREXD:
	case ARM_LDAEXD:
	case ARM_STLEXD: {
		const MCRegisterClass *MRC =
			MCRegisterInfo_getRegClass(MI->MRI, ARM_GPRRegClassID);
		bool isStore = Opcode == ARM_STREXD || Opcode == ARM_STLEXD;
		unsigned Reg = MCOperand_getReg(
			MCInst_getOperand(MI, isStore ? 1 : 0));

		if (MCRegisterClass_contains(MRC, Reg)) {
			MCInst NewMI;

			MCInst_Init(&NewMI, CS_ARCH_ARM);
			MCInst_setOpcode(&NewMI, Opcode);

			if (isStore)
				MCInst_addOperand2(&NewMI,
						   MCInst_getOperand(MI, 0));

			MCOperand_CreateReg0(
				&NewMI,
				MCRegisterInfo_getMatchingSuperReg(
					MI->MRI, Reg, ARM_gsub_0,
					MCRegisterInfo_getRegClass(
						MI->MRI,
						ARM_GPRPairRegClassID)));

			// Copy the rest operands into NewMI.
			for (unsigned i = isStore ? 3 : 2;
			     i < MCInst_getNumOperands(MI); ++i)
				MCInst_addOperand2(&NewMI,
						   MCInst_getOperand(MI, i));

			printInstruction(&NewMI, Address, O);
			return;
		}
		break;
	}
	case ARM_TSB:
	case ARM_t2TSB:
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);

		SStream_concat0(O, " tsb csync");
		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	case ARM_t2DSB:
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);

		switch (MCOperand_getImm(MCInst_getOperand(MI, (0)))) {
		default:
			if (!printAliasInstr(MI, Address, O))
				printInstruction(MI, Address, O);
			break;
		case 0:
			SStream_concat0(O, " ssbb");
			break;
		case 4:
			SStream_concat0(O, " pssbb");
			break;
		};
		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	}

	if (!isAlias)
		isAlias |= printAliasInstr(MI, Address, O);

add_real_detail:
	MCInst_setIsAlias(MI, isAlias);
	if (!isAlias || !useAliasDetails) {
		map_set_fill_detail_ops(MI, !(isAlias && useAliasDetails));
		if (isAlias)
			SStream_Close(O);
		printInstruction(MI, Address, O);
		if (isAlias)
			SStream_Open(O);
	}
}

const char *ARM_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}

void ARM_LLVM_printInstruction(MCInst *MI, SStream *O,
			       void * /* MCRegisterInfo* */ info)
{
	printInst(MI, O, info);
}
