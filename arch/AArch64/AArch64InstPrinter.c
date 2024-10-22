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

//==-- AArch64InstPrinter.cpp - Convert AArch64 MCInst to assembly syntax --==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an AArch64 MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../Mapping.h"
#include "../../MCInst.h"
#include "../../MCInstPrinter.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "../../utils.h"
#include "AArch64AddressingModes.h"
#include "AArch64BaseInfo.h"
#include "AArch64DisassemblerExtension.h"
#include "AArch64InstPrinter.h"
#include "AArch64Linkage.h"
#include "AArch64Mapping.h"

#define GET_BANKEDREG_IMPL
#include "AArch64GenSystemOperands.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define CONCATs(a, b) CONCATS(a, b)
#define CONCATS(a, b) a##b

#define DEBUG_TYPE "asm-printer"

// BEGIN Static declarations.
// These functions must be declared statically here, because they
// are also defined in the ARM module.
// If they are not static, we fail during linking.

static void printCustomAliasOperand(MCInst *MI, uint64_t Address,
				    unsigned OpIdx, unsigned PrintMethodIdx,
				    SStream *OS);

static void printFPImmOperand(MCInst *MI, unsigned OpNum, SStream *O);

#define DECLARE_printComplexRotationOp(Angle, Remainder) \
	static void CONCAT(printComplexRotationOp, CONCAT(Angle, Remainder))( \
		MCInst * MI, unsigned OpNo, SStream *O);
DECLARE_printComplexRotationOp(180, 90);
DECLARE_printComplexRotationOp(90, 0);

// END Static declarations.

#define GET_INSTRUCTION_NAME
#define PRINT_ALIAS_INSTR
#include "AArch64GenAsmWriter.inc"

void printRegName(SStream *OS, unsigned Reg)
{
	SStream_concat(OS, "%s%s", markup("<reg:"),
		       getRegisterName(Reg, AArch64_NoRegAltName));
	SStream_concat0(OS, markup(">"));
}

void printRegNameAlt(SStream *OS, unsigned Reg, unsigned AltIdx)
{
	SStream_concat(OS, "%s%s", markup("<reg:"),
		       getRegisterName(Reg, AltIdx));
	SStream_concat0(OS, markup(">"));
}

const char *getRegName(unsigned Reg)
{
	return getRegisterName(Reg, AArch64_NoRegAltName);
}

void printInst(MCInst *MI, uint64_t Address, const char *Annot, SStream *O)
{
	bool isAlias = false;
	bool useAliasDetails = map_use_alias_details(MI);
	map_set_fill_detail_ops(MI, useAliasDetails);

	unsigned Opcode = MCInst_getOpcode(MI);

	if (Opcode == AArch64_SYSxt) {
		if (printSysAlias(MI, O)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			if (useAliasDetails)
				return;
		}
	}

	if (Opcode == AArch64_SYSPxt || Opcode == AArch64_SYSPxt_XZR) {
		if (printSyspAlias(MI, O)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			if (useAliasDetails)
				return;
		}
	}

	// RPRFM overlaps PRFM (reg), so try to print it as RPRFM here.
	if ((Opcode == AArch64_PRFMroX) || (Opcode == AArch64_PRFMroW)) {
		if (printRangePrefetchAlias(MI, O, Annot)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			if (useAliasDetails)
				return;
		}
	}

	// SBFM/UBFM should print to a nicer aliased form if possible.
	if (Opcode == AArch64_SBFMXri || Opcode == AArch64_SBFMWri ||
	    Opcode == AArch64_UBFMXri || Opcode == AArch64_UBFMWri) {
		MCOperand *Op0 = MCInst_getOperand(MI, (0));
		MCOperand *Op1 = MCInst_getOperand(MI, (1));
		MCOperand *Op2 = MCInst_getOperand(MI, (2));
		MCOperand *Op3 = MCInst_getOperand(MI, (3));

		bool IsSigned = (Opcode == AArch64_SBFMXri ||
				 Opcode == AArch64_SBFMWri);
		bool Is64Bit = (Opcode == AArch64_SBFMXri ||
				Opcode == AArch64_UBFMXri);
		if (MCOperand_isImm(Op2) && MCOperand_getImm(Op2) == 0 &&
		    MCOperand_isImm(Op3)) {
			const char *AsmMnemonic = NULL;

			switch (MCOperand_getImm(Op3)) {
			default:
				break;
			case 7:
				if (IsSigned)
					AsmMnemonic = "sxtb";
				else if (!Is64Bit)
					AsmMnemonic = "uxtb";
				break;
			case 15:
				if (IsSigned)
					AsmMnemonic = "sxth";
				else if (!Is64Bit)
					AsmMnemonic = "uxth";
				break;
			case 31:
				// *xtw is only valid for signed 64-bit operations.
				if (Is64Bit && IsSigned)
					AsmMnemonic = "sxtw";
				break;
			}

			if (AsmMnemonic) {
				SStream_concat(O, "%s", AsmMnemonic);
				SStream_concat0(O, " ");

				printRegName(O, MCOperand_getReg(Op0));
				SStream_concat0(O, ", ");
				printRegName(O, getWRegFromXReg(
							MCOperand_getReg(Op1)));
				if (detail_is_set(MI) && useAliasDetails) {
					AArch64_set_detail_op_reg(
						MI, 0, MCOperand_getReg(Op0));
					AArch64_set_detail_op_reg(
						MI, 1,
						getWRegFromXReg(
							MCOperand_getReg(Op1)));
					if (strings_match(AsmMnemonic, "uxtb"))
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_UXTB;
					else if (strings_match(AsmMnemonic,
							       "sxtb"))
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_SXTB;
					else if (strings_match(AsmMnemonic,
							       "uxth"))
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_UXTH;
					else if (strings_match(AsmMnemonic,
							       "sxth"))
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_SXTH;
					else if (strings_match(AsmMnemonic,
							       "sxtw"))
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_SXTW;
					else
						AArch64_get_detail_op(MI, -1)
							->ext =
							AARCH64_EXT_INVALID;
				}
				isAlias = true;
				MCInst_setIsAlias(MI, isAlias);
				if (useAliasDetails)
					return;
				else
					goto add_real_detail;
			}
		}

		// All immediate shifts are aliases, implemented using the Bitfield
		// instruction. In all cases the immediate shift amount shift must be in
		// the range 0 to (reg.size -1).
		if (MCOperand_isImm(Op2) && MCOperand_isImm(Op3)) {
			const char *AsmMnemonic = NULL;
			int shift = 0;
			int64_t immr = MCOperand_getImm(Op2);
			int64_t imms = MCOperand_getImm(Op3);
			if (Opcode == AArch64_UBFMWri && imms != 0x1F &&
			    ((imms + 1) == immr)) {
				AsmMnemonic = "lsl";
				shift = 31 - imms;
			} else if (Opcode == AArch64_UBFMXri && imms != 0x3f &&
				   ((imms + 1 == immr))) {
				AsmMnemonic = "lsl";
				shift = 63 - imms;
			} else if (Opcode == AArch64_UBFMWri && imms == 0x1f) {
				AsmMnemonic = "lsr";
				shift = immr;
			} else if (Opcode == AArch64_UBFMXri && imms == 0x3f) {
				AsmMnemonic = "lsr";
				shift = immr;
			} else if (Opcode == AArch64_SBFMWri && imms == 0x1f) {
				AsmMnemonic = "asr";
				shift = immr;
			} else if (Opcode == AArch64_SBFMXri && imms == 0x3f) {
				AsmMnemonic = "asr";
				shift = immr;
			}
			if (AsmMnemonic) {
				SStream_concat(O, "%s", AsmMnemonic);
				SStream_concat0(O, " ");

				printRegName(O, MCOperand_getReg(Op0));
				SStream_concat0(O, ", ");
				printRegName(O, MCOperand_getReg(Op1));
				SStream_concat(O, "%s%s#%d", ", ",
					       markup("<imm:"), shift);
				SStream_concat0(O, markup(">"));
				if (detail_is_set(MI) && useAliasDetails) {
					AArch64_set_detail_op_reg(
						MI, 0, MCOperand_getReg(Op0));
					AArch64_set_detail_op_reg(
						MI, 1, MCOperand_getReg(Op1));
					if (strings_match(AsmMnemonic, "lsl"))
						AArch64_get_detail_op(MI, -1)
							->shift.type =
							AARCH64_SFT_LSL;
					else if (strings_match(AsmMnemonic,
							       "lsr"))
						AArch64_get_detail_op(MI, -1)
							->shift.type =
							AARCH64_SFT_LSR;
					else if (strings_match(AsmMnemonic,
							       "asr"))
						AArch64_get_detail_op(MI, -1)
							->shift.type =
							AARCH64_SFT_ASR;
					else
						AArch64_get_detail_op(MI, -1)
							->shift.type =
							AARCH64_SFT_INVALID;
					AArch64_get_detail_op(MI, -1)
						->shift.value = shift;
				}
				isAlias = true;
				MCInst_setIsAlias(MI, isAlias);
				if (useAliasDetails)
					return;
				else
					goto add_real_detail;
			}
		}

		// SBFIZ/UBFIZ aliases
		if (MCOperand_getImm(Op2) > MCOperand_getImm(Op3)) {
			SStream_concat(O, "%s", (IsSigned ? "sbfiz" : "ubfiz"));
			SStream_concat0(O, " ");

			printRegName(O, MCOperand_getReg(Op0));
			SStream_concat0(O, ", ");
			printRegName(O, MCOperand_getReg(Op1));
			SStream_concat(O, "%s%s", ", ", markup("<imm:"));
			printUInt32Bang(O, (Is64Bit ? 64 : 32) -
						   MCOperand_getImm(Op2));
			SStream_concat(O, "%s%s%s", markup(">"), ", ",
				       markup("<imm:"));
			printInt64Bang(O, MCOperand_getImm(Op3) + 1);
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCOperand_getReg(Op0));
				AArch64_set_detail_op_reg(
					MI, 1, MCOperand_getReg(Op1));
				AArch64_set_detail_op_imm(
					MI, 2, AARCH64_OP_IMM,
					(Is64Bit ? 64 : 32) -
						MCOperand_getImm(Op2));
				AArch64_set_detail_op_imm(
					MI, 3, AARCH64_OP_IMM,
					MCOperand_getImm(Op3) + 1);
			}
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		}

		// Otherwise SBFX/UBFX is the preferred form
		SStream_concat(O, "%s", (IsSigned ? "sbfx" : "ubfx"));
		SStream_concat0(O, " ");

		printRegName(O, MCOperand_getReg(Op0));
		SStream_concat0(O, ", ");
		printRegName(O, MCOperand_getReg(Op1));
		SStream_concat(O, "%s%s", ", ", markup("<imm:"));
		printInt64Bang(O, MCOperand_getImm(Op2));
		SStream_concat(O, "%s%s%s", markup(">"), ", ", markup("<imm:"));
		printInt64Bang(O, MCOperand_getImm(Op3) -
					  MCOperand_getImm(Op2) + 1);
		SStream_concat0(O, markup(">"));
		if (detail_is_set(MI) && useAliasDetails) {
			AArch64_set_detail_op_reg(MI, 0, MCOperand_getReg(Op0));
			AArch64_set_detail_op_reg(MI, 1, MCOperand_getReg(Op1));
			AArch64_set_detail_op_imm(MI, 2, AARCH64_OP_IMM,
						  MCOperand_getImm(Op2));
			AArch64_set_detail_op_imm(
				MI, 3, AARCH64_OP_IMM,
				MCOperand_getImm(Op3) - MCOperand_getImm(Op2) +
					1);
		}
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		if (useAliasDetails)
			return;
		else
			goto add_real_detail;
	}

	if (Opcode == AArch64_BFMXri || Opcode == AArch64_BFMWri) {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		MCOperand *Op0 = MCInst_getOperand(MI, (0)); // Op1 == Op0
		MCOperand *Op2 = MCInst_getOperand(MI, (2));
		int ImmR = MCOperand_getImm(MCInst_getOperand(MI, (3)));
		int ImmS = MCOperand_getImm(MCInst_getOperand(MI, (4)));

		if ((MCOperand_getReg(Op2) == AArch64_WZR ||
		     MCOperand_getReg(Op2) == AArch64_XZR) &&
		    (ImmR == 0 || ImmS < ImmR) &&
		    (AArch64_getFeatureBits(MI->csh->mode,
					    AArch64_FeatureAll) ||
		     AArch64_getFeatureBits(MI->csh->mode,
					    AArch64_HasV8_2aOps))) {
			// BFC takes precedence over its entire range, sligtly differently
			// to BFI.
			int BitWidth = Opcode == AArch64_BFMXri ? 64 : 32;
			int LSB = (BitWidth - ImmR) % BitWidth;
			int Width = ImmS + 1;

			SStream_concat0(O, "bfc ");
			printRegName(O, MCOperand_getReg(Op0));
			SStream_concat(O, "%s%s#%d", ", ", markup("<imm:"),
				       LSB);
			SStream_concat(O, "%s%s%s#%d", markup(">"), ", ",
				       markup("<imm:"), Width);
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCOperand_getReg(Op0));
				AArch64_set_detail_op_imm(MI, 3, AARCH64_OP_IMM,
							  LSB);
				AArch64_set_detail_op_imm(MI, 4, AARCH64_OP_IMM,
							  Width);
			}

			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		} else if (ImmS < ImmR) {
			// BFI alias
			int BitWidth = Opcode == AArch64_BFMXri ? 64 : 32;
			int LSB = (BitWidth - ImmR) % BitWidth;
			int Width = ImmS + 1;

			SStream_concat0(O, "bfi ");
			printRegName(O, MCOperand_getReg(Op0));
			SStream_concat0(O, ", ");
			printRegName(O, MCOperand_getReg(Op2));
			SStream_concat(O, "%s%s#%d", ", ", markup("<imm:"),
				       LSB);
			SStream_concat(O, "%s%s%s#%d", markup(">"), ", ",
				       markup("<imm:"), Width);
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCOperand_getReg(Op0));
				AArch64_set_detail_op_reg(
					MI, 2, MCOperand_getReg(Op2));
				AArch64_set_detail_op_imm(MI, 3, AARCH64_OP_IMM,
							  LSB);
				AArch64_set_detail_op_imm(MI, 4, AARCH64_OP_IMM,
							  Width);
			}
			if (useAliasDetails)
				return;
			else
				goto add_real_detail;
		}

		int LSB = ImmR;
		int Width = ImmS - ImmR + 1;
		// Otherwise BFXIL the preferred form
		SStream_concat0(O, "bfxil ");
		printRegName(O, MCOperand_getReg(Op0));
		SStream_concat0(O, ", ");
		printRegName(O, MCOperand_getReg(Op2));
		SStream_concat(O, "%s%s#%d", ", ", markup("<imm:"), LSB);
		SStream_concat(O, "%s%s%s#%d", markup(">"), ", ",
			       markup("<imm:"), Width);
		SStream_concat0(O, markup(">"));
		if (detail_is_set(MI) && useAliasDetails) {
			AArch64_set_detail_op_reg(MI, 0, MCOperand_getReg(Op0));
			AArch64_set_detail_op_reg(MI, 2, MCOperand_getReg(Op2));
			AArch64_set_detail_op_imm(MI, 3, AARCH64_OP_IMM, LSB);
			AArch64_set_detail_op_imm(MI, 4, AARCH64_OP_IMM, Width);
		}
		if (useAliasDetails)
			return;
	}

	// Symbolic operands for MOVZ, MOVN and MOVK already imply a shift
	// (e.g. :gottprel_g1: is always going to be "lsl #16") so it should not be
	// printed.
	if ((Opcode == AArch64_MOVZXi || Opcode == AArch64_MOVZWi ||
	     Opcode == AArch64_MOVNXi || Opcode == AArch64_MOVNWi) &&
	    MCOperand_isExpr(MCInst_getOperand(MI, (1)))) {
		printUInt64Bang(O, MCInst_getOpVal(MI, 1));
		if (detail_is_set(MI) && useAliasDetails) {
			AArch64_set_detail_op_imm(MI, 1, AARCH64_OP_IMM, MCInst_getOpVal(MI, 1));
		}
	}

	if ((Opcode == AArch64_MOVKXi || Opcode == AArch64_MOVKWi) &&
	    MCOperand_isExpr(MCInst_getOperand(MI, (2)))) {
		printUInt64Bang(O, MCInst_getOpVal(MI, 2));
		if (detail_is_set(MI) && useAliasDetails) {
			AArch64_set_detail_op_imm(MI, 2, AARCH64_OP_IMM, MCInst_getOpVal(MI, 2));
		}
	}

	// MOVZ, MOVN and "ORR wzr, #imm" instructions are aliases for MOV, but
	// their domains overlap so they need to be prioritized. The chain is "MOVZ
	// lsl #0 > MOVZ lsl #N > MOVN lsl #0 > MOVN lsl #N > ORR". The highest
	// instruction that can represent the move is the MOV alias, and the rest
	// get printed normally.
	if ((Opcode == AArch64_MOVZXi || Opcode == AArch64_MOVZWi) &&
	    MCOperand_isImm(MCInst_getOperand(MI, (1))) &&
	    MCOperand_isImm(MCInst_getOperand(MI, (2)))) {
		int RegWidth = Opcode == AArch64_MOVZXi ? 64 : 32;
		int Shift = MCOperand_getImm(MCInst_getOperand(MI, (2)));
		uint64_t Value =
			(uint64_t)MCOperand_getImm(MCInst_getOperand(MI, (1)))
			<< Shift;

		if (AArch64_AM_isMOVZMovAlias(
			    Value, Shift, Opcode == AArch64_MOVZXi ? 64 : 32)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "mov ");
			printRegName(O, MCOperand_getReg(
						MCInst_getOperand(MI, (0))));
			SStream_concat(O, "%s%s", ", ", markup("<imm:"));
			printInt64Bang(O, SignExtend64(Value, RegWidth));
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCInst_getOpVal(MI, 0));
				AArch64_set_detail_op_imm(
					MI, 1, AARCH64_OP_IMM,
					SignExtend64(Value, RegWidth));
			}
			if (useAliasDetails)
				return;
		}
	}

	if ((Opcode == AArch64_MOVNXi || Opcode == AArch64_MOVNWi) &&
	    MCOperand_isImm(MCInst_getOperand(MI, (1))) &&
	    MCOperand_isImm(MCInst_getOperand(MI, (2)))) {
		int RegWidth = Opcode == AArch64_MOVNXi ? 64 : 32;
		int Shift = MCOperand_getImm(MCInst_getOperand(MI, (2)));
		uint64_t Value =
			~((uint64_t)MCOperand_getImm(MCInst_getOperand(MI, (1)))
			  << Shift);
		if (RegWidth == 32)
			Value = Value & 0xffffffff;

		if (AArch64_AM_isMOVNMovAlias(Value, Shift, RegWidth)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "mov ");
			printRegName(O, MCOperand_getReg(
						MCInst_getOperand(MI, (0))));
			SStream_concat(O, "%s%s", ", ", markup("<imm:"));
			printInt64Bang(O, SignExtend64(Value, RegWidth));
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCInst_getOpVal(MI, 0));
				AArch64_set_detail_op_imm(
					MI, 1, AARCH64_OP_IMM,
					SignExtend64(Value, RegWidth));
			}
			if (useAliasDetails)
				return;
		}
	}

	if ((Opcode == AArch64_ORRXri || Opcode == AArch64_ORRWri) &&
	    (MCOperand_getReg(MCInst_getOperand(MI, (1))) == AArch64_XZR ||
	     MCOperand_getReg(MCInst_getOperand(MI, (1))) == AArch64_WZR) &&
	    MCOperand_isImm(MCInst_getOperand(MI, (2)))) {
		int RegWidth = Opcode == AArch64_ORRXri ? 64 : 32;
		uint64_t Value = AArch64_AM_decodeLogicalImmediate(
			MCOperand_getImm(MCInst_getOperand(MI, (2))), RegWidth);
		if (!AArch64_AM_isAnyMOVWMovAlias(Value, RegWidth)) {
			isAlias = true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "mov ");
			printRegName(O, MCOperand_getReg(
						MCInst_getOperand(MI, (0))));
			SStream_concat(O, "%s%s", ", ", markup("<imm:"));
			printInt64Bang(O, SignExtend64(Value, RegWidth));
			SStream_concat0(O, markup(">"));
			if (detail_is_set(MI) && useAliasDetails) {
				AArch64_set_detail_op_reg(
					MI, 0, MCInst_getOpVal(MI, 0));
				AArch64_set_detail_op_imm(
					MI, 2, AARCH64_OP_IMM,
					SignExtend64(Value, RegWidth));
			}
			if (useAliasDetails)
				return;
		}
	}

	if (Opcode == AArch64_SPACE) {
		isAlias = true;
		MCInst_setIsAlias(MI, isAlias);
		SStream_concat1(O, ' ');
		SStream_concat(O, "%s", " SPACE ");
		printInt64(O, MCOperand_getImm(MCInst_getOperand(MI, (1))));
		if (detail_is_set(MI) && useAliasDetails) {
			AArch64_set_detail_op_imm(MI, 1, AARCH64_OP_IMM,
						  MCInst_getOpVal(MI, 1));
		}
		if (useAliasDetails)
			return;
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

bool printRangePrefetchAlias(MCInst *MI, SStream *O, const char *Annot)
{
	unsigned Opcode = MCInst_getOpcode(MI);

#ifndef NDEBUG

#endif

	unsigned PRFOp = MCOperand_getImm(MCInst_getOperand(MI, (0)));
	unsigned Mask = 0x18; // 0b11000
	if ((PRFOp & Mask) != Mask)
		return false; // Rt != '11xxx', it's a PRFM instruction.

	unsigned Rm = MCOperand_getReg(MCInst_getOperand(MI, (2)));

	// "Rm" must be a 64-bit GPR for RPRFM.
	if (MCRegisterInfo_getRegClass(MI->MRI, Rm))
		Rm = MCRegisterInfo_getMatchingSuperReg(
			MI->MRI, Rm, AArch64_sub_32,
			MCRegisterInfo_getRegClass(MI->MRI, Rm));

	unsigned SignExtend = MCOperand_getImm(
		MCInst_getOperand(MI, (3))); // encoded in "option<2>".
	unsigned Shift =
		MCOperand_getImm(MCInst_getOperand(MI, (4))); // encoded in "S".

	unsigned Option0 = (Opcode == AArch64_PRFMroX) ? 1 : 0;

	// encoded in "option<2>:option<0>:S:Rt<2:0>".
	unsigned RPRFOp = (SignExtend << 5) | (Option0 << 4) | (Shift << 3) |
			  (PRFOp & 0x7);

	SStream_concat0(O, "rprfm ");
	const AArch64RPRFM_RPRFM *RPRFM =
		AArch64RPRFM_lookupRPRFMByEncoding(RPRFOp);
	if (RPRFM) {
		SStream_concat0(O, RPRFM->Name);
	} else {
    printUInt32Bang(O, RPRFOp);
    SStream_concat(O, ", ");
	}
  SStream_concat0(O, getRegisterName(Rm, AArch64_NoRegAltName));
	SStream_concat0(O, ", [");
	printOperand(MI, 1, O); // "Rn".
	SStream_concat0(O, "]");

	return true;
}

bool printSysAlias(MCInst *MI, SStream *O)
{
	MCOperand *Op1 = MCInst_getOperand(MI, (0));
	MCOperand *Cn = MCInst_getOperand(MI, (1));
	MCOperand *Cm = MCInst_getOperand(MI, (2));
	MCOperand *Op2 = MCInst_getOperand(MI, (3));

	unsigned Op1Val = MCOperand_getImm(Op1);
	unsigned CnVal = MCOperand_getImm(Cn);
	unsigned CmVal = MCOperand_getImm(Cm);
	unsigned Op2Val = MCOperand_getImm(Op2);

	uint16_t Encoding = Op2Val;
	Encoding |= CmVal << 3;
	Encoding |= CnVal << 7;
	Encoding |= Op1Val << 11;

	bool NeedsReg;
	const char *Ins;
	const char *Name;

	if (CnVal == 7) {
		switch (CmVal) {
		default:
			return false;
		// Maybe IC, maybe Prediction Restriction
		case 1:
			switch (Op1Val) {
			default:
				return false;
			case 0:
				goto Search_IC;
			case 3:
				goto Search_PRCTX;
			}
		// Prediction Restriction aliases
		case 3: {
Search_PRCTX:
			if (Op1Val != 3 || CnVal != 7 || CmVal != 3)
				return false;

			unsigned int Requires =
				Op2Val == 6 ? AArch64_FeatureSPECRES2 :
					      AArch64_FeaturePredRes;
			if (!(AArch64_getFeatureBits(MI->csh->mode,
						     AArch64_FeatureAll) ||
			      AArch64_getFeatureBits(MI->csh->mode, Requires)))
				return false;

			NeedsReg = true;
			switch (Op2Val) {
			default:
				return false;
			case 4:
				Ins = "cfp ";
				break;
			case 5:
				Ins = "dvp ";
				break;
			case 6:
				Ins = "cosp ";
				break;
			case 7:
				Ins = "cpp ";
				break;
			}
			Name = "RCTX";
		} break;
		// IC aliases
		case 5: {
Search_IC: {
	const AArch64IC_IC *IC = AArch64IC_lookupICByEncoding(Encoding);
	if (!IC ||
	    !AArch64_testFeatureList(MI->csh->mode, IC->FeaturesRequired))
		return false;
	if (detail_is_set(MI)) {
		aarch64_sysop sysop = { 0 };
		sysop.reg = IC->SysReg;
		sysop.sub_type = AARCH64_OP_IC;
		AArch64_get_detail_op(MI, 0)->type = AARCH64_OP_SYSREG;
		AArch64_get_detail_op(MI, 0)->sysop = sysop;
		AArch64_inc_op_count(MI);
	}

	NeedsReg = IC->NeedsReg;
	Ins = "ic ";
	Name = IC->Name;
}
		} break;
		// DC aliases
		case 4:
		case 6:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14: {
			const AArch64DC_DC *DC =
				AArch64DC_lookupDCByEncoding(Encoding);
			if (!DC || !AArch64_testFeatureList(
					   MI->csh->mode, DC->FeaturesRequired))
				return false;
			if (detail_is_set(MI)) {
				aarch64_sysop sysop = { 0 };
				sysop.alias = DC->SysAlias;
				sysop.sub_type = AARCH64_OP_DC;
				AArch64_get_detail_op(MI, 0)->type =
					AARCH64_OP_SYSALIAS;
				AArch64_get_detail_op(MI, 0)->sysop = sysop;
				AArch64_inc_op_count(MI);
			}

			NeedsReg = true;
			Ins = "dc ";
			Name = DC->Name;
		} break;
		// AT aliases
		case 8:
		case 9: {
			const AArch64AT_AT *AT =
				AArch64AT_lookupATByEncoding(Encoding);
			if (!AT || !AArch64_testFeatureList(
					   MI->csh->mode, AT->FeaturesRequired))
				return false;

			if (detail_is_set(MI)) {
				aarch64_sysop sysop = { 0 };
				sysop.alias = AT->SysAlias;
				sysop.sub_type = AARCH64_OP_AT;
				AArch64_get_detail_op(MI, 0)->type =
					AARCH64_OP_SYSALIAS;
				AArch64_get_detail_op(MI, 0)->sysop = sysop;
				AArch64_inc_op_count(MI);
			}
			NeedsReg = true;
			Ins = "at ";
			Name = AT->Name;
		} break;
		}
	} else if (CnVal == 8 || CnVal == 9) {
		// TLBI aliases
		const AArch64TLBI_TLBI *TLBI =
			AArch64TLBI_lookupTLBIByEncoding(Encoding);
		if (!TLBI || !AArch64_testFeatureList(MI->csh->mode,
						      TLBI->FeaturesRequired))
			return false;

		if (detail_is_set(MI)) {
			aarch64_sysop sysop = { 0 };
			sysop.reg = TLBI->SysReg;
			sysop.sub_type = AARCH64_OP_TLBI;
			AArch64_get_detail_op(MI, 0)->type = AARCH64_OP_SYSREG;
			AArch64_get_detail_op(MI, 0)->sysop = sysop;
			AArch64_inc_op_count(MI);
		}
		NeedsReg = TLBI->NeedsReg;
		Ins = "tlbi ";
		Name = TLBI->Name;
	} else
		return false;

#define TMP_STR_LEN 32
	char Str[TMP_STR_LEN] = { 0 };
	append_to_str_lower(Str, TMP_STR_LEN, Ins);
	append_to_str_lower(Str, TMP_STR_LEN, Name);
#undef TMP_STR_LEN

	SStream_concat1(O, ' ');
	SStream_concat0(O, Str);
	if (NeedsReg) {
		SStream_concat0(O, ", ");
		printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (4))));
		AArch64_set_detail_op_reg(MI, 4, MCInst_getOpVal(MI, 4));
	}

	return true;
}

bool printSyspAlias(MCInst *MI, SStream *O)
{
	MCOperand *Op1 = MCInst_getOperand(MI, (0));
	MCOperand *Cn = MCInst_getOperand(MI, (1));
	MCOperand *Cm = MCInst_getOperand(MI, (2));
	MCOperand *Op2 = MCInst_getOperand(MI, (3));

	unsigned Op1Val = MCOperand_getImm(Op1);
	unsigned CnVal = MCOperand_getImm(Cn);
	unsigned CmVal = MCOperand_getImm(Cm);
	unsigned Op2Val = MCOperand_getImm(Op2);

	uint16_t Encoding = Op2Val;
	Encoding |= CmVal << 3;
	Encoding |= CnVal << 7;
	Encoding |= Op1Val << 11;

	const char *Ins;
	const char *Name;

	if (CnVal == 8 || CnVal == 9) {
		// TLBIP aliases

		if (CnVal == 9) {
			if (!AArch64_getFeatureBits(MI->csh->mode,
						    AArch64_FeatureAll) ||
			    !AArch64_getFeatureBits(MI->csh->mode,
						    AArch64_FeatureXS))
				return false;
			Encoding &= ~(1 << 7);
		}

		const AArch64TLBI_TLBI *TLBI =
			AArch64TLBI_lookupTLBIByEncoding(Encoding);
		if (!TLBI || !AArch64_testFeatureList(MI->csh->mode,
						      TLBI->FeaturesRequired))
			return false;

		if (detail_is_set(MI)) {
			aarch64_sysop sysop = { 0 };
			sysop.reg = TLBI->SysReg;
			sysop.sub_type = AARCH64_OP_TLBI;
			AArch64_get_detail_op(MI, 0)->type = AARCH64_OP_SYSREG;
			AArch64_get_detail_op(MI, 0)->sysop = sysop;
			AArch64_inc_op_count(MI);
		}
		Ins = "tlbip ";
		Name = TLBI->Name;
	} else
		return false;

#define TMP_STR_LEN 32
	char Str[TMP_STR_LEN] = { 0 };
	append_to_str_lower(Str, TMP_STR_LEN, Ins);
	append_to_str_lower(Str, TMP_STR_LEN, Name);

	if (CnVal == 9) {
		append_to_str_lower(Str, TMP_STR_LEN, "nxs");
	}
#undef TMP_STR_LEN

	SStream_concat1(O, ' ');
	SStream_concat0(O, Str);
	SStream_concat0(O, ", ");
	if (MCOperand_getReg(MCInst_getOperand(MI, (4))) == AArch64_XZR)
		printSyspXzrPair(MI, 4, O);
	else
		CONCAT(printGPRSeqPairsClassOperand, 64)(MI, 4, O);

	return true;
}

#define DEFINE_printMatrix(EltSize) \
	void CONCAT(printMatrix, EltSize)(MCInst * MI, unsigned OpNum, \
					  SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_Matrix, EltSize), OpNum, \
			EltSize); \
		MCOperand *RegOp = MCInst_getOperand(MI, (OpNum)); \
\
		printRegName(O, MCOperand_getReg(RegOp)); \
		switch (EltSize) { \
		case 0: \
			break; \
		case 8: \
			SStream_concat0(O, ".b"); \
			break; \
		case 16: \
			SStream_concat0(O, ".h"); \
			break; \
		case 32: \
			SStream_concat0(O, ".s"); \
			break; \
		case 64: \
			SStream_concat0(O, ".d"); \
			break; \
		case 128: \
			SStream_concat0(O, ".q"); \
			break; \
		default: \
			CS_ASSERT_RET(0 && "Unsupported element size"); \
		} \
	}
DEFINE_printMatrix(64);
DEFINE_printMatrix(32);
DEFINE_printMatrix(16);
DEFINE_printMatrix(0);

#define DEFINE_printMatrixTileVector(IsVertical) \
	void CONCAT(printMatrixTileVector, \
		    IsVertical)(MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, \
			CONCAT(AArch64_OP_GROUP_MatrixTileVector, IsVertical), \
			OpNum, IsVertical); \
		MCOperand *RegOp = MCInst_getOperand(MI, (OpNum)); \
\
		const char *RegName = getRegisterName(MCOperand_getReg(RegOp), \
						      AArch64_NoRegAltName); \
\
		unsigned buf_len = strlen(RegName) + 1; \
		char *Base = cs_mem_calloc(1, buf_len); \
		memcpy(Base, RegName, buf_len); \
		char *Dot = strchr(Base, '.'); \
		if (!Dot) { \
			SStream_concat0(O, RegName); \
			return; \
		} \
		*Dot = '\0'; /* Split string */ \
		char *Suffix = Dot + 1; \
		SStream_concat(O, "%s%s", Base, (IsVertical ? "v" : "h")); \
		SStream_concat1(O, '.'); \
		SStream_concat0(O, Suffix); \
		cs_mem_free(Base); \
	}
DEFINE_printMatrixTileVector(0);
DEFINE_printMatrixTileVector(1);

void printMatrixTile(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_MatrixTile, OpNum);
	MCOperand *RegOp = MCInst_getOperand(MI, (OpNum));

	printRegName(O, MCOperand_getReg(RegOp));
}

void printSVCROp(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SVCROp, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));

	unsigned svcrop = MCOperand_getImm(MO);
	const AArch64SVCR_SVCR *SVCR = AArch64SVCR_lookupSVCRByEncoding(svcrop);

	SStream_concat0(O, SVCR->Name);
}

void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_Operand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op)) {
		unsigned Reg = MCOperand_getReg(Op);
		printRegName(O, Reg);
	} else if (MCOperand_isImm(Op)) {
		Op = MCInst_getOperand(MI, (OpNo));
		SStream_concat(O, "%s", markup("<imm:"));
		printInt64Bang(O, MCOperand_getImm(Op));
		SStream_concat0(O, markup(">"));
	} else {
		printUInt64Bang(O, MCInst_getOpVal(MI, OpNo));
	}
}

void printImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_Imm, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	SStream_concat(O, "%s", markup("<imm:"));
	printInt64Bang(O, MCOperand_getImm(Op));
	SStream_concat0(O, markup(">"));
}

void printImmHex(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_ImmHex, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	SStream_concat(O, "%s", markup("<imm:"));
	printInt64Bang(O, MCOperand_getImm(Op));
	SStream_concat0(O, markup(">"));
}

#define DEFINE_printSImm(Size) \
	void CONCAT(printSImm, Size)(MCInst * MI, unsigned OpNo, SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_SImm, Size), OpNo, Size); \
		MCOperand *Op = MCInst_getOperand(MI, (OpNo)); \
		if (Size == 8) { \
			SStream_concat(O, "%s", markup("<imm:")); \
			printInt32Bang(O, MCOperand_getImm(Op)); \
			SStream_concat0(O, markup(">")); \
		} else if (Size == 16) { \
			SStream_concat(O, "%s", markup("<imm:")); \
			printInt32Bang(O, MCOperand_getImm(Op)); \
			SStream_concat0(O, markup(">")); \
		} else { \
			SStream_concat(O, "%s", markup("<imm:")); \
			printInt64Bang(O, MCOperand_getImm(Op)); \
			SStream_concat0(O, markup(">")); \
		} \
	}
DEFINE_printSImm(16);
DEFINE_printSImm(8);

void printPostIncOperand(MCInst *MI, unsigned OpNo, unsigned Imm, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op)) {
		unsigned Reg = MCOperand_getReg(Op);
		if (Reg == AArch64_XZR) {
			SStream_concat(O, "%s", markup("<imm:"));
			printUInt64Bang(O, Imm);
			SStream_concat0(O, markup(">"));
		} else
			printRegName(O, Reg);
	} else
		CS_ASSERT_RET(0 && "unknown operand kind in printPostIncOperand64");
}

void printVRegOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_VRegOperand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));

	unsigned Reg = MCOperand_getReg(Op);
	printRegNameAlt(O, Reg, AArch64_vreg);
}

void printSysCROperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SysCROperand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));

	SStream_concat(O, "%s", "c");
	printUInt32(O, MCOperand_getImm(Op));
	SStream_concat1(O, '\0');
}

void printAddSubImm(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AddSubImm, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		unsigned Val = (MCOperand_getImm(MO) & 0xfff);

		unsigned Shift = AArch64_AM_getShiftValue(
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum + 1))));
		SStream_concat(O, "%s", markup("<imm:"));
		printUInt32Bang(O, (Val));
		SStream_concat0(O, markup(">"));
		if (Shift != 0) {
			printShifter(MI, OpNum + 1, O);
		}
	} else {
		printShifter(MI, OpNum + 1, O);
	}
}

#define DEFINE_printLogicalImm(T) \
	void CONCAT(printLogicalImm, T)(MCInst * MI, unsigned OpNum, \
					SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_LogicalImm, T), OpNum, sizeof(T)); \
		uint64_t Val = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		SStream_concat(O, "%s", markup("<imm:")); \
		printUInt64Bang(O, (AArch64_AM_decodeLogicalImmediate( \
					   Val, 8 * sizeof(T)))); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printLogicalImm(int64_t);
DEFINE_printLogicalImm(int32_t);
DEFINE_printLogicalImm(int8_t);
DEFINE_printLogicalImm(int16_t);

void printShifter(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_Shifter, OpNum);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	// LSL #0 should not be printed.
	if (AArch64_AM_getShiftType(Val) == AArch64_AM_LSL &&
	    AArch64_AM_getShiftValue(Val) == 0)
		return;
	SStream_concat(
		O, "%s%s%s%s#%d", ", ",
		AArch64_AM_getShiftExtendName(AArch64_AM_getShiftType(Val)),
		" ", markup("<imm:"), AArch64_AM_getShiftValue(Val));
	SStream_concat0(O, markup(">"));
}

void printShiftedRegister(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_ShiftedRegister, OpNum);
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	printShifter(MI, OpNum + 1, O);
}

void printExtendedRegister(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_ExtendedRegister, OpNum);
	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	printArithExtend(MI, OpNum + 1, O);
}

void printArithExtend(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_ArithExtend, OpNum);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	AArch64_AM_ShiftExtendType ExtType = AArch64_AM_getArithExtendType(Val);
	unsigned ShiftVal = AArch64_AM_getArithShiftValue(Val);

	// If the destination or first source register operand is [W]SP, print
	// UXTW/UXTX as LSL, and if the shift amount is also zero, print nothing at
	// all.
	if (ExtType == AArch64_AM_UXTW || ExtType == AArch64_AM_UXTX) {
		unsigned Dest = MCOperand_getReg(MCInst_getOperand(MI, (0)));
		unsigned Src1 = MCOperand_getReg(MCInst_getOperand(MI, (1)));
		if (((Dest == AArch64_SP || Src1 == AArch64_SP) &&
		     ExtType == AArch64_AM_UXTX) ||
		    ((Dest == AArch64_WSP || Src1 == AArch64_WSP) &&
		     ExtType == AArch64_AM_UXTW)) {
			if (ShiftVal != 0) {
				SStream_concat(O, "%s%s", ", lsl ",
					       markup("<imm:"));
				printUInt32Bang(O, ShiftVal);
				SStream_concat0(O, markup(">"));
			}
			return;
		}
	}
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, AArch64_AM_getShiftExtendName(ExtType));
	if (ShiftVal != 0) {
		SStream_concat(O, "%s%s#%d", " ", markup("<imm:"), ShiftVal);
		SStream_concat0(O, markup(">"));
	}
}

static void printMemExtendImpl(bool SignExtend, bool DoShift, unsigned Width,
			       char SrcRegKind, SStream *O, bool getUseMarkup)
{
	// sxtw, sxtx, uxtw or lsl (== uxtx)
	bool IsLSL = !SignExtend && SrcRegKind == 'x';
	if (IsLSL)
		SStream_concat0(O, "lsl");
	else {
		SStream_concat(O, "%c%s", (SignExtend ? 's' : 'u'), "xt");
		SStream_concat1(O, SrcRegKind);
	}

	if (DoShift || IsLSL) {
		SStream_concat0(O, " ");
		if (getUseMarkup)
			SStream_concat0(O, "<imm:");
		unsigned ShiftAmount = DoShift ? Log2_32(Width / 8) : 0;
		SStream_concat(O, "%s%d", "#", ShiftAmount);
		if (getUseMarkup)
			SStream_concat0(O, ">");
	}
}

void printMemExtend(MCInst *MI, unsigned OpNum, SStream *O, char SrcRegKind,
		    unsigned Width)
{
	bool SignExtend = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	bool DoShift = MCOperand_getImm(MCInst_getOperand(MI, (OpNum + 1)));
	printMemExtendImpl(SignExtend, DoShift, Width, SrcRegKind, O,
			   getUseMarkup());
}

#define DEFINE_printRegWithShiftExtend(SignExtend, ExtWidth, SrcRegKind, \
				       Suffix) \
	void CONCAT(printRegWithShiftExtend, \
		    CONCAT(SignExtend, \
			   CONCAT(ExtWidth, CONCAT(SrcRegKind, Suffix))))( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_4( \
			MI, \
			CONCAT(CONCAT(CONCAT(CONCAT(AArch64_OP_GROUP_RegWithShiftExtend, \
						    SignExtend), \
					     ExtWidth), \
				      SrcRegKind), \
			       Suffix), \
			OpNum, SignExtend, ExtWidth, CHAR(SrcRegKind), \
			CHAR(Suffix)); \
		printOperand(MI, OpNum, O); \
		if (CHAR(Suffix) == 's' || CHAR(Suffix) == 'd') { \
			SStream_concat1(O, '.'); \
			SStream_concat1(O, CHAR(Suffix)); \
			SStream_concat1(O, '\0'); \
		} else \
			CS_ASSERT_RET((CHAR(Suffix) == '0') && \
			       "Unsupported suffix size"); \
		bool DoShift = ExtWidth != 8; \
		if (SignExtend || DoShift || CHAR(SrcRegKind) == 'w') { \
			SStream_concat0(O, ", "); \
			printMemExtendImpl(SignExtend, DoShift, ExtWidth, \
					   CHAR(SrcRegKind), O, \
					   getUseMarkup()); \
		} \
	}
DEFINE_printRegWithShiftExtend(false, 8, x, d);
DEFINE_printRegWithShiftExtend(true, 8, w, d);
DEFINE_printRegWithShiftExtend(false, 8, w, d);
DEFINE_printRegWithShiftExtend(false, 8, x, 0);
DEFINE_printRegWithShiftExtend(true, 8, w, s);
DEFINE_printRegWithShiftExtend(false, 8, w, s);
DEFINE_printRegWithShiftExtend(false, 64, x, d);
DEFINE_printRegWithShiftExtend(true, 64, w, d);
DEFINE_printRegWithShiftExtend(false, 64, w, d);
DEFINE_printRegWithShiftExtend(false, 64, x, 0);
DEFINE_printRegWithShiftExtend(true, 64, w, s);
DEFINE_printRegWithShiftExtend(false, 64, w, s);
DEFINE_printRegWithShiftExtend(false, 16, x, d);
DEFINE_printRegWithShiftExtend(true, 16, w, d);
DEFINE_printRegWithShiftExtend(false, 16, w, d);
DEFINE_printRegWithShiftExtend(false, 16, x, 0);
DEFINE_printRegWithShiftExtend(true, 16, w, s);
DEFINE_printRegWithShiftExtend(false, 16, w, s);
DEFINE_printRegWithShiftExtend(false, 32, x, d);
DEFINE_printRegWithShiftExtend(true, 32, w, d);
DEFINE_printRegWithShiftExtend(false, 32, w, d);
DEFINE_printRegWithShiftExtend(false, 32, x, 0);
DEFINE_printRegWithShiftExtend(true, 32, w, s);
DEFINE_printRegWithShiftExtend(false, 32, w, s);
DEFINE_printRegWithShiftExtend(false, 8, x, s);
DEFINE_printRegWithShiftExtend(false, 16, x, s);
DEFINE_printRegWithShiftExtend(false, 32, x, s);
DEFINE_printRegWithShiftExtend(false, 64, x, s);
DEFINE_printRegWithShiftExtend(false, 128, x, 0);

#define DEFINE_printPredicateAsCounter(EltSize) \
	void CONCAT(printPredicateAsCounter, \
		    EltSize)(MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, \
			CONCAT(AArch64_OP_GROUP_PredicateAsCounter, EltSize), \
			OpNum, EltSize); \
		unsigned Reg = \
			MCOperand_getReg(MCInst_getOperand(MI, (OpNum))); \
		if (Reg < AArch64_PN0 || Reg > AArch64_PN15) \
			CS_ASSERT_RET(0 && \
			       "Unsupported predicate-as-counter register"); \
		SStream_concat(O, "%s", "pn"); \
		printUInt32(O, (Reg - AArch64_PN0)); \
		switch (EltSize) { \
		case 0: \
			break; \
		case 8: \
			SStream_concat0(O, ".b"); \
			break; \
		case 16: \
			SStream_concat0(O, ".h"); \
			break; \
		case 32: \
			SStream_concat0(O, ".s"); \
			break; \
		case 64: \
			SStream_concat0(O, ".d"); \
			break; \
		default: \
			CS_ASSERT_RET(0 && "Unsupported element size"); \
		} \
	}
DEFINE_printPredicateAsCounter(8);
DEFINE_printPredicateAsCounter(64);
DEFINE_printPredicateAsCounter(16);
DEFINE_printPredicateAsCounter(32);
DEFINE_printPredicateAsCounter(0);

void printCondCode(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_CondCode, OpNum);
	AArch64CC_CondCode CC = (AArch64CC_CondCode)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, AArch64CC_getCondCodeName(CC));
}

void printInverseCondCode(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_InverseCondCode, OpNum);
	AArch64CC_CondCode CC = (AArch64CC_CondCode)MCOperand_getImm(
		MCInst_getOperand(MI, (OpNum)));
	SStream_concat0(O, AArch64CC_getCondCodeName(
				   AArch64CC_getInvertedCondCode(CC)));
}

void printAMNoIndex(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AMNoIndex, OpNum);
	SStream_concat0(O, "[");

	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	SStream_concat0(O, "]");
}

#define DEFINE_printImmScale(Scale) \
	void CONCAT(printImmScale, Scale)(MCInst * MI, unsigned OpNum, \
					  SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_ImmScale, Scale), OpNum, \
			Scale); \
		SStream_concat(O, "%s", markup("<imm:")); \
		printInt32Bang(O, Scale *MCOperand_getImm( \
					  MCInst_getOperand(MI, (OpNum)))); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printImmScale(8);
DEFINE_printImmScale(2);
DEFINE_printImmScale(4);
DEFINE_printImmScale(16);
DEFINE_printImmScale(32);
DEFINE_printImmScale(3);

#define DEFINE_printImmRangeScale(Scale, Offset) \
	void CONCAT(printImmRangeScale, CONCAT(Scale, Offset))( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_2( \
			MI, \
			CONCAT(CONCAT(AArch64_OP_GROUP_ImmRangeScale, Scale), \
			       Offset), \
			OpNum, Scale, Offset); \
		unsigned FirstImm = \
			Scale * \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		printUInt32(O, (FirstImm)); \
		SStream_concat(O, "%s", ":"); \
		printUInt32(O, (FirstImm + Offset)); \
		SStream_concat1(O, '\0'); \
	}
DEFINE_printImmRangeScale(2, 1);
DEFINE_printImmRangeScale(4, 3);

void printUImm12Offset(MCInst *MI, unsigned OpNum, unsigned Scale, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		SStream_concat(O, "%s", markup("<imm:"));
		printUInt32Bang(O, (MCOperand_getImm(MO) * Scale));
		SStream_concat0(O, markup(">"));
	} else {
		printUInt64Bang(O, MCOperand_getImm(MO));
	}
}

void printAMIndexedWB(MCInst *MI, unsigned OpNum, unsigned Scale, SStream *O)
{
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNum + 1));
	SStream_concat0(O, "[");

	printRegName(O, MCOperand_getReg(MCInst_getOperand(MI, (OpNum))));
	if (MCOperand_isImm(MO1)) {
		SStream_concat(O, "%s%s", ", ", markup("<imm:"));
		printUInt32Bang(O, MCOperand_getImm(MO1) * Scale);
		SStream_concat0(O, markup(">"));
	} else {
		printUInt64Bang(O, MCOperand_getImm(MO1));
	}
	SStream_concat0(O, "]");
}

void printRPRFMOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_RPRFMOperand, OpNum);
	unsigned prfop = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	const AArch64PRFM_PRFM *PRFM =
		AArch64RPRFM_lookupRPRFMByEncoding(prfop);
	if (PRFM) {
		SStream_concat0(O, PRFM->Name);
		return;
	}

	printUInt32Bang(O, (prfop));
	SStream_concat1(O, '\0');
}

#define DEFINE_printPrefetchOp(IsSVEPrefetch) \
	void CONCAT(printPrefetchOp, \
		    IsSVEPrefetch)(MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_1(MI, \
					CONCAT(AArch64_OP_GROUP_PrefetchOp, \
					       IsSVEPrefetch), \
					OpNum, IsSVEPrefetch); \
		unsigned prfop = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		if (IsSVEPrefetch) { \
			const AArch64SVEPRFM_SVEPRFM *PRFM = \
				AArch64SVEPRFM_lookupSVEPRFMByEncoding(prfop); \
			if (PRFM) { \
				SStream_concat0(O, PRFM->Name); \
				return; \
			} \
		} else { \
			const AArch64PRFM_PRFM *PRFM = \
				AArch64PRFM_lookupPRFMByEncoding(prfop); \
			if (PRFM && \
			    AArch64_testFeatureList(MI->csh->mode, \
						    PRFM->FeaturesRequired)) { \
				SStream_concat0(O, PRFM->Name); \
				return; \
			} \
		} \
\
		SStream_concat(O, "%s", markup("<imm:")); \
		printUInt32Bang(O, (prfop)); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printPrefetchOp(false);
DEFINE_printPrefetchOp(true);

void printPSBHintOp(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_PSBHintOp, OpNum);
	unsigned psbhintop = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	const AArch64PSBHint_PSB *PSB =
		AArch64PSBHint_lookupPSBByEncoding(psbhintop);
	if (PSB)
		SStream_concat0(O, PSB->Name);
	else {
		SStream_concat(O, "%s", markup("<imm:"));
		SStream_concat1(O, '#');
		printUInt32Bang(O, (psbhintop));
		SStream_concat0(O, markup(">"));
	}
}

void printBTIHintOp(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_BTIHintOp, OpNum);
	unsigned btihintop = MCOperand_getImm(MCInst_getOperand(MI, (OpNum))) ^
			     32;
	const AArch64BTIHint_BTI *BTI =
		AArch64BTIHint_lookupBTIByEncoding(btihintop);
	if (BTI)
		SStream_concat0(O, BTI->Name);
	else {
		SStream_concat(O, "%s", markup("<imm:"));
		printUInt32Bang(O, (btihintop));
		SStream_concat0(O, markup(">"));
	}
}

static void printFPImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_FPImmOperand, OpNum);
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	float FPImm = MCOperand_isDFPImm(MO) ?
			      BitsToDouble(MCOperand_getImm(MO)) :
			      AArch64_AM_getFPImmFloat(MCOperand_getImm(MO));

	// 8 decimal places are enough to perfectly represent permitted floats.
	SStream_concat(O, "%s", markup("<imm:"));
	SStream_concat(O, "#%.8f", FPImm);
	SStream_concat0(O, markup(">"));
}

static unsigned getNextVectorRegister(unsigned Reg, unsigned Stride /* = 1 */)
{
	while (Stride--) {
		switch (Reg) {
		default:
			CS_ASSERT_RET_VAL(0 && "Vector register expected!", 0);
		case AArch64_Q0:
			Reg = AArch64_Q1;
			break;
		case AArch64_Q1:
			Reg = AArch64_Q2;
			break;
		case AArch64_Q2:
			Reg = AArch64_Q3;
			break;
		case AArch64_Q3:
			Reg = AArch64_Q4;
			break;
		case AArch64_Q4:
			Reg = AArch64_Q5;
			break;
		case AArch64_Q5:
			Reg = AArch64_Q6;
			break;
		case AArch64_Q6:
			Reg = AArch64_Q7;
			break;
		case AArch64_Q7:
			Reg = AArch64_Q8;
			break;
		case AArch64_Q8:
			Reg = AArch64_Q9;
			break;
		case AArch64_Q9:
			Reg = AArch64_Q10;
			break;
		case AArch64_Q10:
			Reg = AArch64_Q11;
			break;
		case AArch64_Q11:
			Reg = AArch64_Q12;
			break;
		case AArch64_Q12:
			Reg = AArch64_Q13;
			break;
		case AArch64_Q13:
			Reg = AArch64_Q14;
			break;
		case AArch64_Q14:
			Reg = AArch64_Q15;
			break;
		case AArch64_Q15:
			Reg = AArch64_Q16;
			break;
		case AArch64_Q16:
			Reg = AArch64_Q17;
			break;
		case AArch64_Q17:
			Reg = AArch64_Q18;
			break;
		case AArch64_Q18:
			Reg = AArch64_Q19;
			break;
		case AArch64_Q19:
			Reg = AArch64_Q20;
			break;
		case AArch64_Q20:
			Reg = AArch64_Q21;
			break;
		case AArch64_Q21:
			Reg = AArch64_Q22;
			break;
		case AArch64_Q22:
			Reg = AArch64_Q23;
			break;
		case AArch64_Q23:
			Reg = AArch64_Q24;
			break;
		case AArch64_Q24:
			Reg = AArch64_Q25;
			break;
		case AArch64_Q25:
			Reg = AArch64_Q26;
			break;
		case AArch64_Q26:
			Reg = AArch64_Q27;
			break;
		case AArch64_Q27:
			Reg = AArch64_Q28;
			break;
		case AArch64_Q28:
			Reg = AArch64_Q29;
			break;
		case AArch64_Q29:
			Reg = AArch64_Q30;
			break;
		case AArch64_Q30:
			Reg = AArch64_Q31;
			break;
		// Vector lists can wrap around.
		case AArch64_Q31:
			Reg = AArch64_Q0;
			break;
		case AArch64_Z0:
			Reg = AArch64_Z1;
			break;
		case AArch64_Z1:
			Reg = AArch64_Z2;
			break;
		case AArch64_Z2:
			Reg = AArch64_Z3;
			break;
		case AArch64_Z3:
			Reg = AArch64_Z4;
			break;
		case AArch64_Z4:
			Reg = AArch64_Z5;
			break;
		case AArch64_Z5:
			Reg = AArch64_Z6;
			break;
		case AArch64_Z6:
			Reg = AArch64_Z7;
			break;
		case AArch64_Z7:
			Reg = AArch64_Z8;
			break;
		case AArch64_Z8:
			Reg = AArch64_Z9;
			break;
		case AArch64_Z9:
			Reg = AArch64_Z10;
			break;
		case AArch64_Z10:
			Reg = AArch64_Z11;
			break;
		case AArch64_Z11:
			Reg = AArch64_Z12;
			break;
		case AArch64_Z12:
			Reg = AArch64_Z13;
			break;
		case AArch64_Z13:
			Reg = AArch64_Z14;
			break;
		case AArch64_Z14:
			Reg = AArch64_Z15;
			break;
		case AArch64_Z15:
			Reg = AArch64_Z16;
			break;
		case AArch64_Z16:
			Reg = AArch64_Z17;
			break;
		case AArch64_Z17:
			Reg = AArch64_Z18;
			break;
		case AArch64_Z18:
			Reg = AArch64_Z19;
			break;
		case AArch64_Z19:
			Reg = AArch64_Z20;
			break;
		case AArch64_Z20:
			Reg = AArch64_Z21;
			break;
		case AArch64_Z21:
			Reg = AArch64_Z22;
			break;
		case AArch64_Z22:
			Reg = AArch64_Z23;
			break;
		case AArch64_Z23:
			Reg = AArch64_Z24;
			break;
		case AArch64_Z24:
			Reg = AArch64_Z25;
			break;
		case AArch64_Z25:
			Reg = AArch64_Z26;
			break;
		case AArch64_Z26:
			Reg = AArch64_Z27;
			break;
		case AArch64_Z27:
			Reg = AArch64_Z28;
			break;
		case AArch64_Z28:
			Reg = AArch64_Z29;
			break;
		case AArch64_Z29:
			Reg = AArch64_Z30;
			break;
		case AArch64_Z30:
			Reg = AArch64_Z31;
			break;
		// Vector lists can wrap around.
		case AArch64_Z31:
			Reg = AArch64_Z0;
			break;
		case AArch64_P0:
			Reg = AArch64_P1;
			break;
		case AArch64_P1:
			Reg = AArch64_P2;
			break;
		case AArch64_P2:
			Reg = AArch64_P3;
			break;
		case AArch64_P3:
			Reg = AArch64_P4;
			break;
		case AArch64_P4:
			Reg = AArch64_P5;
			break;
		case AArch64_P5:
			Reg = AArch64_P6;
			break;
		case AArch64_P6:
			Reg = AArch64_P7;
			break;
		case AArch64_P7:
			Reg = AArch64_P8;
			break;
		case AArch64_P8:
			Reg = AArch64_P9;
			break;
		case AArch64_P9:
			Reg = AArch64_P10;
			break;
		case AArch64_P10:
			Reg = AArch64_P11;
			break;
		case AArch64_P11:
			Reg = AArch64_P12;
			break;
		case AArch64_P12:
			Reg = AArch64_P13;
			break;
		case AArch64_P13:
			Reg = AArch64_P14;
			break;
		case AArch64_P14:
			Reg = AArch64_P15;
			break;
		// Vector lists can wrap around.
		case AArch64_P15:
			Reg = AArch64_P0;
			break;
		}
	}
	return Reg;
}

#define DEFINE_printGPRSeqPairsClassOperand(size) \
	void CONCAT(printGPRSeqPairsClassOperand, \
		    size)(MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, \
			CONCAT(AArch64_OP_GROUP_GPRSeqPairsClassOperand, \
			       size), \
			OpNum, size); \
		CS_ASSERT_RET((size == 64 || size == 32) && \
		       "Template parameter must be either 32 or 64"); \
		unsigned Reg = \
			MCOperand_getReg(MCInst_getOperand(MI, (OpNum))); \
\
		unsigned Sube = (size == 32) ? AArch64_sube32 : \
					       AArch64_sube64; \
		unsigned Subo = (size == 32) ? AArch64_subo32 : \
					       AArch64_subo64; \
\
		unsigned Even = MCRegisterInfo_getSubReg(MI->MRI, Reg, Sube); \
		unsigned Odd = MCRegisterInfo_getSubReg(MI->MRI, Reg, Subo); \
		printRegName(O, Even); \
		SStream_concat0(O, ", "); \
		printRegName(O, Odd); \
	}
DEFINE_printGPRSeqPairsClassOperand(32);
DEFINE_printGPRSeqPairsClassOperand(64);

#define DEFINE_printMatrixIndex(Scale) \
	void CONCAT(printMatrixIndex, Scale)(MCInst * MI, unsigned OpNum, \
					     SStream *O) \
	{ \
		AArch64_add_cs_detail_1(MI, CONCAT(AArch64_OP_GROUP_MatrixIndex, Scale), \
			      OpNum, Scale); \
		printInt64(O, Scale *MCOperand_getImm( \
				      MCInst_getOperand(MI, (OpNum)))); \
	}
DEFINE_printMatrixIndex(8);
DEFINE_printMatrixIndex(0);
DEFINE_printMatrixIndex(1);

void printMatrixTileList(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_MatrixTileList, OpNum);
	unsigned MaxRegs = 8;
	unsigned RegMask = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

	unsigned NumRegs = 0;
	for (unsigned I = 0; I < MaxRegs; ++I)
		if ((RegMask & (1 << I)) != 0)
			++NumRegs;

	SStream_concat0(O, "{");
	unsigned Printed = 0;
	for (unsigned I = 0; I < MaxRegs; ++I) {
		unsigned Reg = RegMask & (1 << I);
		if (Reg == 0)
			continue;
		printRegName(O, AArch64_ZAD0 + I);
		if (Printed + 1 != NumRegs)
			SStream_concat0(O, ", ");
		++Printed;
	}
	SStream_concat0(O, "}");
}

void printVectorList(MCInst *MI, unsigned OpNum, SStream *O,
		     const char *LayoutSuffix)
{
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));

	SStream_concat0(O, "{ ");

	// Work out how many registers there are in the list (if there is an actual
	// list).
	unsigned NumRegs = 1;
	if (MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI, AArch64_DDRegClassID),
		    Reg) ||
	    MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPR2RegClassID),
		    Reg) ||
	    MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI, AArch64_QQRegClassID),
		    Reg) ||
	    MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI, AArch64_PPR2RegClassID),
		    Reg) ||
	    MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI,
					       AArch64_ZPR2StridedRegClassID),
		    Reg))
		NumRegs = 2;
	else if (MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_DDDRegClassID),
			 Reg) ||
		 MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_ZPR3RegClassID),
			 Reg) ||
		 MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_QQQRegClassID),
			 Reg))
		NumRegs = 3;
	else if (MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_DDDDRegClassID),
			 Reg) ||
		 MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_ZPR4RegClassID),
			 Reg) ||
		 MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(MI->MRI,
						    AArch64_QQQQRegClassID),
			 Reg) ||
		 MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(
				 MI->MRI, AArch64_ZPR4StridedRegClassID),
			 Reg))
		NumRegs = 4;

	unsigned Stride = 1;
	if (MCRegisterClass_contains(
		    MCRegisterInfo_getRegClass(MI->MRI,
					       AArch64_ZPR2StridedRegClassID),
		    Reg))
		Stride = 8;
	else if (MCRegisterClass_contains(
			 MCRegisterInfo_getRegClass(
				 MI->MRI, AArch64_ZPR4StridedRegClassID),
			 Reg))
		Stride = 4;

	// Now forget about the list and find out what the first register is.
	if (MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_dsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_dsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_qsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_qsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_zsub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_zsub0);
	else if (MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_psub0))
		Reg = MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_psub0);

	// If it's a D-reg, we need to promote it to the equivalent Q-reg before
	// printing (otherwise getRegisterName fails).
	if (MCRegisterClass_contains(MCRegisterInfo_getRegClass(
					     MI->MRI, AArch64_FPR64RegClassID),
				     Reg)) {
		const MCRegisterClass *FPR128RC = MCRegisterInfo_getRegClass(
			MI->MRI, AArch64_FPR128RegClassID);
		Reg = MCRegisterInfo_getMatchingSuperReg(
			MI->MRI, Reg, AArch64_dsub, FPR128RC);
	}

	if ((MCRegisterClass_contains(
		     MCRegisterInfo_getRegClass(MI->MRI, AArch64_ZPRRegClassID),
		     Reg) ||
	     MCRegisterClass_contains(
		     MCRegisterInfo_getRegClass(MI->MRI, AArch64_PPRRegClassID),
		     Reg)) &&
	    NumRegs > 1 && Stride == 1 &&
	    // Do not print the range when the last register is lower than the
	    // first. Because it is a wrap-around register.
	    Reg < getNextVectorRegister(Reg, NumRegs - 1)) {
		printRegName(O, Reg);
		SStream_concat0(O, LayoutSuffix);
		if (NumRegs > 1) {
			// Set of two sve registers should be separated by ','
			const char *split_char = NumRegs == 2 ? ", " : " - ";
			SStream_concat0(O, split_char);
			printRegName(O,
				     (getNextVectorRegister(Reg, NumRegs - 1)));
			SStream_concat0(O, LayoutSuffix);
		}
	} else {
		for (unsigned i = 0; i < NumRegs;
		     ++i, Reg = getNextVectorRegister(Reg, Stride)) {
			// wrap-around sve register
			if (MCRegisterClass_contains(
				    MCRegisterInfo_getRegClass(
					    MI->MRI, AArch64_ZPRRegClassID),
				    Reg) ||
			    MCRegisterClass_contains(
				    MCRegisterInfo_getRegClass(
					    MI->MRI, AArch64_PPRRegClassID),
				    Reg))
				printRegName(O, Reg);
			else
				printRegNameAlt(O, Reg, AArch64_vreg);
			SStream_concat0(O, LayoutSuffix);
			if (i + 1 != NumRegs)
				SStream_concat0(O, ", ");
		}
	}
	SStream_concat0(O, " }");
}

void printImplicitlyTypedVectorList(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_ImplicitlyTypedVectorList,
				OpNum);
	printVectorList(MI, OpNum, O, "");
}

#define DEFINE_printTypedVectorList(NumLanes, LaneKind) \
	void CONCAT(printTypedVectorList, CONCAT(NumLanes, LaneKind))( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_2( \
			MI, \
			CONCAT(CONCAT(AArch64_OP_GROUP_TypedVectorList, \
				      NumLanes), \
			       LaneKind), \
			OpNum, NumLanes, CHAR(LaneKind)); \
		if (CHAR(LaneKind) == '0') { \
			printVectorList(MI, OpNum, O, ""); \
			return; \
		} \
		char Suffix[32]; \
		if (NumLanes) \
			cs_snprintf(Suffix, sizeof(Suffix), ".%u%c", NumLanes, \
				    CHAR(LaneKind)); \
		else \
			cs_snprintf(Suffix, sizeof(Suffix), ".%c", \
				    CHAR(LaneKind)); \
\
		printVectorList(MI, OpNum, O, ((const char *)&Suffix)); \
	}
DEFINE_printTypedVectorList(0, b);
DEFINE_printTypedVectorList(0, d);
DEFINE_printTypedVectorList(0, h);
DEFINE_printTypedVectorList(0, s);
DEFINE_printTypedVectorList(0, q);
DEFINE_printTypedVectorList(16, b);
DEFINE_printTypedVectorList(1, d);
DEFINE_printTypedVectorList(2, d);
DEFINE_printTypedVectorList(2, s);
DEFINE_printTypedVectorList(4, h);
DEFINE_printTypedVectorList(4, s);
DEFINE_printTypedVectorList(8, b);
DEFINE_printTypedVectorList(8, h);
DEFINE_printTypedVectorList(0, 0);

#define DEFINE_printVectorIndex(Scale) \
	void CONCAT(printVectorIndex, Scale)(MCInst * MI, unsigned OpNum, \
					     SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_VectorIndex, Scale), \
			OpNum, Scale); \
		SStream_concat(O, "%s", "["); \
		printUInt64(O, Scale *MCOperand_getImm( \
				       MCInst_getOperand(MI, (OpNum)))); \
		SStream_concat0(O, "]"); \
	}
DEFINE_printVectorIndex(1);
DEFINE_printVectorIndex(8);

void printAlignedLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AlignedLabel, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	// If the label has already been resolved to an immediate offset (say, when
	// we're running the disassembler), just print the immediate.
	if (MCOperand_isImm(Op)) {
		SStream_concat0(O, markup("<imm:"));
		int64_t Offset = MCOperand_getImm(Op) * 4;
		if (MI->csh->PrintBranchImmAsAddress)
			printUInt64(O, (Address + Offset));
		else {
			printUInt64Bang(O, (Offset));
		}
		SStream_concat0(O, markup(">"));
		return;
	}

	printUInt64Bang(O, MCOperand_getImm(Op));
}

void printAdrLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AdrLabel, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	// If the label has already been resolved to an immediate offset (say, when
	// we're running the disassembler), just print the immediate.
	if (MCOperand_isImm(Op)) {
		const int64_t Offset = MCOperand_getImm(Op);
		SStream_concat0(O, markup("<imm:"));
		if (MI->csh->PrintBranchImmAsAddress)
			printUInt64(O, ((Address & -4) + Offset));
		else {
			printUInt64Bang(O, Offset);
		}
		SStream_concat0(O, markup(">"));
		return;
	}

	printUInt64Bang(O, MCOperand_getImm(Op));
}

void printAdrpLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AdrpLabel, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	// If the label has already been resolved to an immediate offset (say, when
	// we're running the disassembler), just print the immediate.
	if (MCOperand_isImm(Op)) {
		const int64_t Offset = MCOperand_getImm(Op) * 4096;
		SStream_concat0(O, markup("<imm:"));
		if (MI->csh->PrintBranchImmAsAddress)
			printUInt64(O, ((Address & -4096) + Offset));
		else {
			printUInt64Bang(O, Offset);
		}
		SStream_concat0(O, markup(">"));
		return;
	}

	printUInt64Bang(O, MCOperand_getImm(Op));
}

void printAdrAdrpLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O) {
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_AdrAdrpLabel, OpNum);
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

  // If the label has already been resolved to an immediate offset (say, when
  // we're running the disassembler), just print the immediate.
	if (MCOperand_isImm(Op)) {
		int64_t Offset = MCOperand_getImm(Op);
    if (MCInst_getOpcode(MI) == AArch64_ADRP) {
      Offset = Offset * 4096;
      Address = Address & -4096;
    }
		SStream_concat0(O, markup(">"));
		if (MI->csh->PrintBranchImmAsAddress)
			printUInt64(O, (Address + Offset));
		else {
			printUInt64Bang(O, Offset);
		}
		SStream_concat0(O, markup(">"));
    return;
  }

	printUInt64Bang(O, MCOperand_getImm(Op));
}

void printBarrierOption(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_BarrierOption, OpNo);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	unsigned Opcode = MCInst_getOpcode(MI);

	const char *Name;
	if (Opcode == AArch64_ISB) {
		const AArch64ISB_ISB *ISB = AArch64ISB_lookupISBByEncoding(Val);
		Name = ISB ? ISB->Name : "";
	} else if (Opcode == AArch64_TSB) {
		const AArch64TSB_TSB *TSB = AArch64TSB_lookupTSBByEncoding(Val);
		Name = TSB ? TSB->Name : "";
	} else {
		const AArch64DB_DB *DB = AArch64DB_lookupDBByEncoding(Val);
		Name = DB ? DB->Name : "";
	}
	if (Name[0] != '\0')
		SStream_concat0(O, Name);
	else {
		SStream_concat(O, "%s", markup("<imm:"));
		printUInt32Bang(O, Val);
		SStream_concat0(O, markup(">"));
	}
}

void printBarriernXSOption(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_BarriernXSOption, OpNo);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

	const char *Name;
	const AArch64DBnXS_DBnXS *DB = AArch64DBnXS_lookupDBnXSByEncoding(Val);
	Name = DB ? DB->Name : "";

	if (Name[0] != '\0')
		SStream_concat0(O, Name);
	else {
		SStream_concat(O, "%s%s%s", markup("<imm:"), "#", Val);
		SStream_concat0(O, markup(">"));
	}
}

static bool isValidSysReg(const AArch64SysReg_SysReg *Reg, bool Read,
			  unsigned mode)
{
	return (Reg && (Read ? Reg->Readable : Reg->Writeable) &&
		AArch64_testFeatureList(mode, Reg->FeaturesRequired));
}

// Looks up a system register either by encoding or by name. Some system
// registers share the same encoding between different architectures,
// therefore a tablegen lookup by encoding will return an entry regardless
// of the register's predication on a specific subtarget feature. To work
// around this problem we keep an alternative name for such registers and
// look them up by that name if the first lookup was unsuccessful.
static const AArch64SysReg_SysReg *lookupSysReg(unsigned Val, bool Read,
						unsigned mode)
{
	const AArch64SysReg_SysReg *Reg =
		AArch64SysReg_lookupSysRegByEncoding(Val);

	if (Reg && !isValidSysReg(Reg, Read, mode))
		Reg = AArch64SysReg_lookupSysRegByName(Reg->AltName);

	return Reg;
}

void printMRSSystemRegister(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_MRSSystemRegister, OpNo);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

	// Horrible hack for the one register that has identical encodings but
	// different names in MSR and MRS. Because of this, one of MRS and MSR is
	// going to get the wrong entry
	if (Val == AARCH64_SYSREG_DBGDTRRX_EL0) {
		SStream_concat0(O, "DBGDTRRX_EL0");
		return;
	}

	// Horrible hack for two different registers having the same encoding.
	if (Val == AARCH64_SYSREG_TRCEXTINSELR) {
		SStream_concat0(O, "TRCEXTINSELR");
		return;
	}

	const AArch64SysReg_SysReg *Reg =
		lookupSysReg(Val, true /*Read*/, MI->csh->mode);

	if (isValidSysReg(Reg, true /*Read*/, MI->csh->mode))
		SStream_concat0(O, Reg->Name);
	else {
		char result[AARCH64_GRS_LEN + 1] = { 0 };
		AArch64SysReg_genericRegisterString(Val, result);
		SStream_concat0(O, result);
	}
}

void printMSRSystemRegister(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_MSRSystemRegister, OpNo);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

	// Horrible hack for the one register that has identical encodings but
	// different names in MSR and MRS. Because of this, one of MRS and MSR is
	// going to get the wrong entry
	if (Val == AARCH64_SYSREG_DBGDTRTX_EL0) {
		SStream_concat0(O, "DBGDTRTX_EL0");
		return;
	}

	// Horrible hack for two different registers having the same encoding.
	if (Val == AARCH64_SYSREG_TRCEXTINSELR) {
		SStream_concat0(O, "TRCEXTINSELR");
		return;
	}

	const AArch64SysReg_SysReg *Reg =
		lookupSysReg(Val, false /*Read*/, MI->csh->mode);

	if (isValidSysReg(Reg, false /*Read*/, MI->csh->mode))
		SStream_concat0(O, Reg->Name);
	else {
		char result[AARCH64_GRS_LEN + 1] = { 0 };
		AArch64SysReg_genericRegisterString(Val, result);
		SStream_concat0(O, result);
	}
}

void printSystemPStateField(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SystemPStateField, OpNo);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

	const AArch64PState_PStateImm0_15 *PStateImm15 =
		AArch64PState_lookupPStateImm0_15ByEncoding(Val);
	const AArch64PState_PStateImm0_1 *PStateImm1 =
		AArch64PState_lookupPStateImm0_1ByEncoding(Val);
	if (PStateImm15 &&
	    AArch64_testFeatureList(MI->csh->mode,
				    PStateImm15->FeaturesRequired))
		SStream_concat0(O, PStateImm15->Name);
	else if (PStateImm1 &&
		 AArch64_testFeatureList(MI->csh->mode,
					 PStateImm1->FeaturesRequired))
		SStream_concat0(O, PStateImm1->Name);
	else {
		printUInt32Bang(O, (Val));
		SStream_concat1(O, '\0');
	}
}

void printSIMDType10Operand(MCInst *MI, unsigned OpNo, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SIMDType10Operand, OpNo);
	unsigned RawVal = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	uint64_t Val = AArch64_AM_decodeAdvSIMDModImmType10(RawVal);
	SStream_concat(O, "%s#%#016llx", markup("<imm:"), Val);
	SStream_concat0(O, markup(">"));
}

#define DEFINE_printComplexRotationOp(Angle, Remainder) \
	static void CONCAT(printComplexRotationOp, CONCAT(Angle, Remainder))( \
		MCInst * MI, unsigned OpNo, SStream *O) \
	{ \
		AArch64_add_cs_detail_2( \
			MI, \
			CONCAT(CONCAT(AArch64_OP_GROUP_ComplexRotationOp, \
				      Angle), \
			       Remainder), \
			OpNo, Angle, Remainder); \
		unsigned Val = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNo))); \
		SStream_concat(O, "%s", markup("<imm:")); \
		SStream_concat(O, "#%d", (Val * Angle) + Remainder); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printComplexRotationOp(180, 90);
DEFINE_printComplexRotationOp(90, 0);

void printSVEPattern(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SVEPattern, OpNum);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	const AArch64SVEPredPattern_SVEPREDPAT *Pat =
		AArch64SVEPredPattern_lookupSVEPREDPATByEncoding(Val);
	if (Pat)
		SStream_concat0(O, Pat->Name);
	else
		printUInt32Bang(O, Val);
}

void printSVEVecLenSpecifier(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SVEVecLenSpecifier, OpNum);
	unsigned Val = MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
	// Pattern has only 1 bit
	if (Val > 1)
		CS_ASSERT_RET(0 && "Invalid vector length specifier");
	const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *Pat =
		AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByEncoding(
			Val);
	if (Pat)
		SStream_concat0(O, Pat->Name);
}

#define DEFINE_printSVERegOp(suffix) \
	void CONCAT(printSVERegOp, suffix)(MCInst * MI, unsigned OpNum, \
					   SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_SVERegOp, suffix), OpNum, \
			CHAR(suffix)); \
		switch (CHAR(suffix)) { \
		case '0': \
		case 'b': \
		case 'h': \
		case 's': \
		case 'd': \
		case 'q': \
			break; \
		default: \
			CS_ASSERT_RET(0 && "Invalid kind specifier."); \
		} \
\
		unsigned Reg = \
			MCOperand_getReg(MCInst_getOperand(MI, (OpNum))); \
		printRegName(O, Reg); \
		if (CHAR(suffix) != '0') { \
			SStream_concat1(O, '.'); \
			SStream_concat1(O, CHAR(suffix)); \
		} \
	}
DEFINE_printSVERegOp(b);
DEFINE_printSVERegOp(d);
DEFINE_printSVERegOp(h);
DEFINE_printSVERegOp(s);
DEFINE_printSVERegOp(0);
DEFINE_printSVERegOp(q);

#define DECLARE_printImmSVE_S32(T) \
	void CONCAT(printImmSVE, T)(T Val, SStream * O) \
	{ \
		printInt32Bang(O, Val); \
	}
DECLARE_printImmSVE_S32(int16_t);
DECLARE_printImmSVE_S32(int8_t);
DECLARE_printImmSVE_S32(int32_t);

#define DECLARE_printImmSVE_U32(T) \
	void CONCAT(printImmSVE, T)(T Val, SStream * O) \
	{ \
		printUInt32Bang(O, Val); \
	}
DECLARE_printImmSVE_U32(uint16_t);
DECLARE_printImmSVE_U32(uint8_t);
DECLARE_printImmSVE_U32(uint32_t);

#define DECLARE_printImmSVE_S64(T) \
	void CONCAT(printImmSVE, T)(T Val, SStream * O) \
	{ \
		printInt64Bang(O, Val); \
	}
DECLARE_printImmSVE_S64(int64_t);

#define DECLARE_printImmSVE_U64(T) \
	void CONCAT(printImmSVE, T)(T Val, SStream * O) \
	{ \
		printUInt64Bang(O, Val); \
	}
DECLARE_printImmSVE_U64(uint64_t);

#define DEFINE_isSignedType(T) \
	static inline bool CONCAT(isSignedType, T)() \
	{ \
		return CHAR(T) == 'i'; \
	}
DEFINE_isSignedType(int8_t);
DEFINE_isSignedType(int16_t);
DEFINE_isSignedType(int32_t);
DEFINE_isSignedType(int64_t);
DEFINE_isSignedType(uint8_t);
DEFINE_isSignedType(uint16_t);
DEFINE_isSignedType(uint32_t);
DEFINE_isSignedType(uint64_t);

#define DEFINE_printImm8OptLsl(T) \
	void CONCAT(printImm8OptLsl, T)(MCInst * MI, unsigned OpNum, \
					SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_Imm8OptLsl, T), OpNum, sizeof(T)); \
		unsigned UnscaledVal = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		unsigned Shift = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum + 1))); \
\
		if ((UnscaledVal == 0) && \
		    (AArch64_AM_getShiftValue(Shift) != 0)) { \
			SStream_concat(O, "%s", markup("<imm:")); \
			SStream_concat1(O, '#'); \
			printUInt64(O, (UnscaledVal)); \
			SStream_concat0(O, markup(">")); \
			printShifter(MI, OpNum + 1, O); \
			return; \
		} \
\
		T Val; \
		if (CONCAT(isSignedType, T)()) \
			Val = (int8_t)UnscaledVal * \
			      (1 << AArch64_AM_getShiftValue(Shift)); \
		else \
			Val = (uint8_t)UnscaledVal * \
			      (1 << AArch64_AM_getShiftValue(Shift)); \
\
		CONCAT(printImmSVE, T)(Val, O); \
	}
DEFINE_printImm8OptLsl(int16_t);
DEFINE_printImm8OptLsl(int8_t);
DEFINE_printImm8OptLsl(int64_t);
DEFINE_printImm8OptLsl(int32_t);
DEFINE_printImm8OptLsl(uint16_t);
DEFINE_printImm8OptLsl(uint8_t);
DEFINE_printImm8OptLsl(uint64_t);
DEFINE_printImm8OptLsl(uint32_t);

#define DEFINE_printSVELogicalImm(T) \
	void CONCAT(printSVELogicalImm, T)(MCInst * MI, unsigned OpNum, \
					   SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_SVELogicalImm, T), OpNum, \
			sizeof(T)); \
		typedef T SignedT; \
		typedef CONCATS(u, T) UnsignedT; \
\
		uint64_t Val = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		UnsignedT PrintVal = \
			AArch64_AM_decodeLogicalImmediate(Val, 64); \
\
		if ((int16_t)PrintVal == (SignedT)PrintVal) \
			CONCAT(printImmSVE, T)((T)PrintVal, O); \
		else if ((uint16_t)PrintVal == PrintVal) \
			CONCAT(printImmSVE, T)(PrintVal, O); \
		else { \
			SStream_concat(O, "%s", markup("<imm:")); \
			printUInt64Bang(O, ((uint64_t)PrintVal)); \
			SStream_concat0(O, markup(">")); \
		} \
	}
DEFINE_printSVELogicalImm(int16_t);
DEFINE_printSVELogicalImm(int32_t);
DEFINE_printSVELogicalImm(int64_t);

#define DEFINE_printZPRasFPR(Width) \
	void CONCAT(printZPRasFPR, Width)(MCInst * MI, unsigned OpNum, \
					  SStream *O) \
	{ \
		AArch64_add_cs_detail_1( \
			MI, CONCAT(AArch64_OP_GROUP_ZPRasFPR, Width), OpNum, \
			Width); \
		unsigned Base; \
		switch (Width) { \
		case 8: \
			Base = AArch64_B0; \
			break; \
		case 16: \
			Base = AArch64_H0; \
			break; \
		case 32: \
			Base = AArch64_S0; \
			break; \
		case 64: \
			Base = AArch64_D0; \
			break; \
		case 128: \
			Base = AArch64_Q0; \
			break; \
		default: \
			CS_ASSERT_RET(0 && "Unsupported width"); \
		} \
		unsigned Reg = \
			MCOperand_getReg(MCInst_getOperand(MI, (OpNum))); \
		printRegName(O, Reg - AArch64_Z0 + Base); \
	}
DEFINE_printZPRasFPR(8);
DEFINE_printZPRasFPR(64);
DEFINE_printZPRasFPR(16);
DEFINE_printZPRasFPR(32);
DEFINE_printZPRasFPR(128);

#define DEFINE_printExactFPImm(ImmIs0, ImmIs1) \
	void CONCAT(printExactFPImm, CONCAT(ImmIs0, ImmIs1))( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		AArch64_add_cs_detail_2( \
			MI, \
			CONCAT(CONCAT(AArch64_OP_GROUP_ExactFPImm, ImmIs0), \
			       ImmIs1), \
			OpNum, ImmIs0, ImmIs1); \
		const AArch64ExactFPImm_ExactFPImm *Imm0Desc = \
			AArch64ExactFPImm_lookupExactFPImmByEnum(ImmIs0); \
		const AArch64ExactFPImm_ExactFPImm *Imm1Desc = \
			AArch64ExactFPImm_lookupExactFPImmByEnum(ImmIs1); \
		unsigned Val = \
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum))); \
		SStream_concat(O, "%s%s%s", markup("<imm:"), "#", \
			       (Val ? Imm1Desc->Repr : Imm0Desc->Repr)); \
		SStream_concat0(O, markup(">")); \
	}
DEFINE_printExactFPImm(AArch64ExactFPImm_half, AArch64ExactFPImm_one);
DEFINE_printExactFPImm(AArch64ExactFPImm_zero, AArch64ExactFPImm_one);
DEFINE_printExactFPImm(AArch64ExactFPImm_half, AArch64ExactFPImm_two);

void printGPR64as32(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_GPR64as32, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	printRegName(O, getWRegFromXReg(Reg));
}

void printGPR64x8(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_GPR64x8, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));
	printRegName(O,
		     MCRegisterInfo_getSubReg(MI->MRI, Reg, AArch64_x8sub_0));
}

void printSyspXzrPair(MCInst *MI, unsigned OpNum, SStream *O)
{
	AArch64_add_cs_detail_0(MI, AArch64_OP_GROUP_SyspXzrPair, OpNum);
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, (OpNum)));

	SStream_concat(O, "%s%s", getRegisterName(Reg, AArch64_NoRegAltName),
		       ", ");
	SStream_concat0(O, getRegisterName(Reg, AArch64_NoRegAltName));
}

const char *AArch64_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}

void AArch64_LLVM_printInstruction(MCInst *MI, SStream *O,
				   void * /* MCRegisterInfo* */ info)
{
	printInst(MI, MI->address, "", O);
}
