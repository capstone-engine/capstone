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

//===-- PPCInstPrinter.cpp - Convert PPC MCInst to assembly syntax --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an PPC MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <capstone/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../LEB128.h"
#include "../../Mapping.h"
#include "../../MCInst.h"
#include "../../MCInstPrinter.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "PPCInstrInfo.h"
#include "PPCLinkage.h"
#include "PPCMCTargetDesc.h"
#include "PPCMapping.h"
#include "PPCPredicates.h"
#include "PPCRegisterInfo.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

extern const MCInstrDesc PPCInsts[];

// Static function declarations. These are functions which have the same identifiers
// over all architectures. Therefor they need to be static.
#ifndef CAPSTONE_DIET
static void printCustomAliasOperand(MCInst *MI, uint64_t Address,
				    unsigned OpIdx, unsigned PrintMethodIdx,
				    SStream *O);
#endif

static const char *getRegisterName(unsigned RegNo);

/// showRegistersWithPercentPrefix - Check if this register name should be
/// printed with a percentage symbol as prefix.
static inline bool showRegistersWithPercentPrefix(const MCInst *MI,
						  const char *RegName)
{
	if ((MI->csh->syntax & CS_OPT_SYNTAX_NOREGNAME) ||
	    !(MI->csh->syntax & CS_OPT_SYNTAX_PERCENT) ||
	    PPC_getFeatureBits(MI->csh->mode, PPC_FeatureModernAIXAs))
		return false;

	switch (RegName[0]) {
	default:
		return false;
	case 'r':
	case 'f':
	case 'q':
	case 'v':
	case 'c':
		return true;
	}
}

/// getVerboseConditionalRegName - This method expands the condition register
/// when requested explicitly or targeting Darwin.
static inline const char *getVerboseConditionRegName(const MCInst *MI,
						     unsigned RegNum,
						     unsigned RegEncoding)
{
	if (MI->csh->syntax & CS_OPT_SYNTAX_NOREGNAME)
		return NULL;
	if (RegNum < PPC_CR0EQ || RegNum > PPC_CR7UN)
		return NULL;
	const char *CRBits[] = {
		"lt",	    "gt",	"eq",	    "un",	"4*cr1+lt",
		"4*cr1+gt", "4*cr1+eq", "4*cr1+un", "4*cr2+lt", "4*cr2+gt",
		"4*cr2+eq", "4*cr2+un", "4*cr3+lt", "4*cr3+gt", "4*cr3+eq",
		"4*cr3+un", "4*cr4+lt", "4*cr4+gt", "4*cr4+eq", "4*cr4+un",
		"4*cr5+lt", "4*cr5+gt", "4*cr5+eq", "4*cr5+un", "4*cr6+lt",
		"4*cr6+gt", "4*cr6+eq", "4*cr6+un", "4*cr7+lt", "4*cr7+gt",
		"4*cr7+eq", "4*cr7+un"
	};
	return CRBits[RegEncoding];
}

// showRegistersWithPrefix - This method determines whether registers
// should be number-only or include the prefix.
static inline bool showRegistersWithPrefix(const MCInst *MI)
{
	return !(MI->csh->syntax & CS_OPT_SYNTAX_NOREGNAME);
}

static inline void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_Operand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op)) {
		unsigned Reg = MCOperand_getReg(Op);
		if (!MI->csh->ShowVSRNumsAsVR)
			Reg = PPCInstrInfo_getRegNumForOperand(
				MCInstrDesc_get(MCInst_getOpcode(MI),
						PPCDescs.Insts,
						ARR_SIZE(PPCDescs.Insts)),
				Reg, OpNo);

		const char *RegName;
		RegName = getVerboseConditionRegName(
			MI, Reg, MI->MRI->RegEncodingTable[Reg]);
		if (RegName == NULL)
			RegName = getRegisterName(Reg);
		if (showRegistersWithPercentPrefix(MI, RegName))
			SStream_concat0(O, "%");
		if (!showRegistersWithPrefix(MI))
			RegName = PPCRegisterInfo_stripRegisterPrefix(RegName);

		SStream_concat0(O, RegName);
		return;
	}

	if (MCOperand_isImm(Op)) {
		printInt64(O, MCOperand_getImm(Op));
		return;
	}
}

static inline void printPredicateOperand(MCInst *MI, unsigned OpNo, SStream *O,
					 const char *Modifier)
{
	PPC_add_cs_detail_1(MI, PPC_OP_GROUP_PredicateOperand, OpNo, Modifier);
	unsigned Code = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

	if (strcmp(Modifier, "cc") == 0) {
		switch ((PPC_Predicate)Code) {
		default:
			CS_ASSERT_RET(0 && "Invalid predicate code");
		case PPC_PRED_LT_MINUS:
		case PPC_PRED_LT_PLUS:
		case PPC_PRED_LT:
			SStream_concat0(O, "lt");
			return;
		case PPC_PRED_LE_MINUS:
		case PPC_PRED_LE_PLUS:
		case PPC_PRED_LE:
			SStream_concat0(O, "le");
			return;
		case PPC_PRED_EQ_MINUS:
		case PPC_PRED_EQ_PLUS:
		case PPC_PRED_EQ:
			SStream_concat0(O, "eq");
			return;
		case PPC_PRED_GE_MINUS:
		case PPC_PRED_GE_PLUS:
		case PPC_PRED_GE:
			SStream_concat0(O, "ge");
			return;
		case PPC_PRED_GT_MINUS:
		case PPC_PRED_GT_PLUS:
		case PPC_PRED_GT:
			SStream_concat0(O, "gt");
			return;
		case PPC_PRED_NE_MINUS:
		case PPC_PRED_NE_PLUS:
		case PPC_PRED_NE:
			SStream_concat0(O, "ne");
			return;
		case PPC_PRED_UN_MINUS:
		case PPC_PRED_UN_PLUS:
		case PPC_PRED_UN:
			SStream_concat0(O, "un");
			return;
		case PPC_PRED_NU_MINUS:
		case PPC_PRED_NU_PLUS:
		case PPC_PRED_NU:
			SStream_concat0(O, "nu");
			return;
		case PPC_PRED_BIT_SET:
		case PPC_PRED_BIT_UNSET:
			CS_ASSERT_RET(0 && "Invalid use of bit predicate code");
		}
		CS_ASSERT_RET(0 && "Invalid predicate code");
	}

	if (strcmp(Modifier, "pm") == 0) {
		switch ((PPC_Predicate)Code) {
		default:
			CS_ASSERT_RET(0 && "Invalid predicate code");
		case PPC_PRED_LT:
		case PPC_PRED_LE:
		case PPC_PRED_EQ:
		case PPC_PRED_GE:
		case PPC_PRED_GT:
		case PPC_PRED_NE:
		case PPC_PRED_UN:
		case PPC_PRED_NU:
			return;
		case PPC_PRED_LT_MINUS:
		case PPC_PRED_LE_MINUS:
		case PPC_PRED_EQ_MINUS:
		case PPC_PRED_GE_MINUS:
		case PPC_PRED_GT_MINUS:
		case PPC_PRED_NE_MINUS:
		case PPC_PRED_UN_MINUS:
		case PPC_PRED_NU_MINUS:
			SStream_concat0(O, "-");
			return;
		case PPC_PRED_LT_PLUS:
		case PPC_PRED_LE_PLUS:
		case PPC_PRED_EQ_PLUS:
		case PPC_PRED_GE_PLUS:
		case PPC_PRED_GT_PLUS:
		case PPC_PRED_NE_PLUS:
		case PPC_PRED_UN_PLUS:
		case PPC_PRED_NU_PLUS:
			SStream_concat0(O, "+");
			return;
		case PPC_PRED_BIT_SET:
		case PPC_PRED_BIT_UNSET:
			CS_ASSERT_RET(0 && "Invalid use of bit predicate code");
		}
		CS_ASSERT_RET(0 && "Invalid predicate code");
	}

	printOperand(MI, OpNo + 1, O);
}

static inline void printATBitsAsHint(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_ATBitsAsHint, OpNo);
	unsigned Code = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	if (Code == 2)
		SStream_concat0(O, "-");
	else if (Code == 3)
		SStream_concat0(O, "+");
}

static inline void printU1ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U1ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 1 && "Invalid u1imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU2ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U2ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 3 && "Invalid u2imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU3ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U3ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 8 && "Invalid u3imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU4ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U4ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 15 && "Invalid u4imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printS5ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_S5ImmOperand, OpNo);
	int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	Value = SignExtend32((Value), 5);
	printInt32(O, (int)Value);
}

static inline void printImmZeroOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_ImmZeroOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value == 0 && "Operand must be zero");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU5ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U5ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 31 && "Invalid u5imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU6ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U6ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 63 && "Invalid u6imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU7ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U7ImmOperand, OpNo);
	unsigned int Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 127 && "Invalid u7imm argument!");
	printUInt32(O, (unsigned int)Value);
}

// Operands of BUILD_VECTOR are signed and we use this to print operands
// of XXSPLTIB which are unsigned. So we simply truncate to 8 bits and
// print as unsigned.
static inline void printU8ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U8ImmOperand, OpNo);
	unsigned char Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 255 && "Invalid u8imm argument!");
	printUInt32(O, (unsigned int)Value);
}

static inline void printU10ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U10ImmOperand, OpNo);
	unsigned short Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 1023 && "Invalid u10imm argument!");
	printUInt32(O, (unsigned short)Value);
}

static inline void printU12ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U12ImmOperand, OpNo);
	unsigned short Value = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(Value <= 4095 && "Invalid u12imm argument!");
	printUInt32(O, (unsigned short)Value);
}

static inline void printS12ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_S12ImmOperand, OpNo);
	if (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		int Imm = (int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		Imm = SignExtend32(Imm, 12);
		printInt32(O, Imm);
	} else
		printOperand(MI, OpNo, O);
}

static inline void printMemRegImmPS(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);

	printS12ImmOperand(MI, OpNo, O);
	SStream_concat0(O, "(");
	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");

	set_mem_access(MI, false);
}

static inline void printS16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_S16ImmOperand, OpNo);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNo))))
		printInt32(O, (short)MCOperand_getImm(
				      MCInst_getOperand(MI, (OpNo))));
	else
		printOperand(MI, OpNo, O);
}

static inline void printS34ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_S34ImmOperand, OpNo);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNo)))) {
		long long Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));

		printInt64(O, (long long)Value);
	} else
		printOperand(MI, OpNo, O);
}

static inline void printU16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_U16ImmOperand, OpNo);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNo))))
		printUInt32(O, (unsigned short)MCOperand_getImm(
				       MCInst_getOperand(MI, (OpNo))));
	else
		printOperand(MI, OpNo, O);
}

static inline void printBranchOperand(MCInst *MI, uint64_t Address,
				      unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_BranchOperand, OpNo);
	if (!MCOperand_isImm(MCInst_getOperand(MI, (OpNo)))) {
		printOperand(MI, OpNo, O);
		return;
	}
	int32_t Imm = SignExtend32(
		((unsigned)MCOperand_getImm(MCInst_getOperand(MI, (OpNo)))
		 << 2),
		32);
	if (MI->csh->PrintBranchImmAsAddress) {
		uint64_t Target = Address + Imm;
		if (!IS_64BIT(MI->csh->mode))
			Target &= 0xffffffff;
		printUInt64(O, (Target));
	} else {
		// Branches can take an immediate operand. This is used by the branch
		// selection pass to print, for example `.+8` (for ELF) or `$+8` (for
		// AIX) to express an eight byte displacement from the program counter.
		if (!PPC_getFeatureBits(MI->csh->mode, PPC_FeatureModernAIXAs))
			SStream_concat0(O, ".");
		else
			SStream_concat0(O, "$");

		if (Imm >= 0)
			SStream_concat0(O, "+");
		printInt32(O, Imm);
	}
}

static inline void printAbsBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_AbsBranchOperand, OpNo);
	if (!MCOperand_isImm(MCInst_getOperand(MI, (OpNo)))) {
		printOperand(MI, OpNo, O);
		return;
	}

	printUInt64(O,
		    ((unsigned)MCOperand_getImm(MCInst_getOperand(MI, (OpNo)))
		     << 2));
}

static inline void printcrbitm(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_crbitm, OpNo);
	unsigned CCReg = MCOperand_getReg(MCInst_getOperand(MI, (OpNo)));
	unsigned RegNo;
	switch (CCReg) {
	default:
		CS_ASSERT_RET(0 && "Unknown CR register");
	case PPC_CR0:
		RegNo = 0;
		break;
	case PPC_CR1:
		RegNo = 1;
		break;
	case PPC_CR2:
		RegNo = 2;
		break;
	case PPC_CR3:
		RegNo = 3;
		break;
	case PPC_CR4:
		RegNo = 4;
		break;
	case PPC_CR5:
		RegNo = 5;
		break;
	case PPC_CR6:
		RegNo = 6;
		break;
	case PPC_CR7:
		RegNo = 7;
		break;
	}
	printUInt32(O, (0x80 >> RegNo));
}

static inline void printMemRegImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_MemRegImm, OpNo);
	printS16ImmOperand(MI, OpNo, O);
	SStream_concat0(O, "(");

	if (MCOperand_getReg(MCInst_getOperand(MI, (OpNo + 1))) == PPC_R0)
		SStream_concat0(O, "0");
	else
		printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static inline void printMemRegImmHash(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_MemRegImmHash, OpNo);
	printInt32(O, MCOperand_getImm(MCInst_getOperand(MI, (OpNo))));
	SStream_concat0(O, "(");

	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static inline void printMemRegImm34PCRel(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_MemRegImm34PCRel, OpNo);
	printS34ImmOperand(MI, OpNo, O);
	SStream_concat0(O, "(");

	printImmZeroOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static inline void printMemRegImm34(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_MemRegImm34, OpNo);
	printS34ImmOperand(MI, OpNo, O);
	SStream_concat0(O, "(");

	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static inline void printMemRegReg(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_MemRegReg, OpNo);
	// When used as the base register, r0 reads constant zero rather than
	// the value contained in the register.  For this reason, the darwin
	// assembler requires that we print r0 as 0 (no r) when used as the base.
	if (MCOperand_getReg(MCInst_getOperand(MI, (OpNo))) == PPC_R0)
		SStream_concat0(O, "0");
	else
		printOperand(MI, OpNo, O);
	SStream_concat0(O, ", ");
	printOperand(MI, OpNo + 1, O);
	set_mem_access(MI, false);
}

static inline void printTLSCall(MCInst *MI, unsigned OpNo, SStream *O)
{
	PPC_add_cs_detail_0(MI, PPC_OP_GROUP_TLSCall, OpNo);

	// Expression logic removed.

	set_mem_access(MI, true);
	SStream_concat0(O, "(");

	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

#define PRINT_ALIAS_INSTR
#include "PPCGenAsmWriter.inc"

static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O)
{
	bool isAlias = false;
	bool useAliasDetails = false;
	// Customize printing of the addis instruction on AIX. When an operand is a
	// symbol reference, the instruction syntax is changed to look like a load
	// operation, i.e:
	//     Transform:  addis $rD, $rA, $src --> addis $rD, $src($rA).
	if (PPC_getFeatureBits(MI->csh->mode, PPC_FeatureModernAIXAs) &&
	    (MCInst_getOpcode(MI) == PPC_ADDIS8 ||
	     MCInst_getOpcode(MI) == PPC_ADDIS) &&
	    MCOperand_isExpr(MCInst_getOperand(MI, (2)))) {
		SStream_concat0(O, "\taddis ");
		printOperand(MI, 0, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 2, O);
		SStream_concat0(O, "(");
		printOperand(MI, 1, O);
		SStream_concat0(O, ")");
		return;
	}

	// Check if the last operand is an expression with the variant kind
	// VK_PPC_PCREL_OPT. If this is the case then this is a linker optimization
	// relocation and the .reloc directive needs to be added.
	unsigned LastOp = MCInst_getNumOperands(MI) - 1;
	if (MCInst_getNumOperands(MI) > 1) {
		MCOperand *Operand = MCInst_getOperand(MI, (LastOp));
		if (MCOperand_isExpr(Operand)) {
			CS_ASSERT_RET(0 && "Expressions not supported.");
		}
	}

	// Check for slwi/srwi mnemonics.
	if (MCInst_getOpcode(MI) == PPC_RLWINM) {
		unsigned char SH = MCOperand_getImm(MCInst_getOperand(MI, (2)));
		unsigned char MB = MCOperand_getImm(MCInst_getOperand(MI, (3)));
		unsigned char ME = MCOperand_getImm(MCInst_getOperand(MI, (4)));
		bool useSubstituteMnemonic = false;
		if (SH <= 31 && MB == 0 && ME == (31 - SH)) {
			SStream_concat0(O, "slwi ");
			useSubstituteMnemonic = true;
		}
		if (SH <= 31 && MB == (32 - SH) && ME == 31) {
			SStream_concat0(O, "srwi ");
			useSubstituteMnemonic = true;
			SH = 32 - SH;
		}
		useAliasDetails |= map_use_alias_details(MI);
		map_set_fill_detail_ops(MI, useAliasDetails &&
						    useSubstituteMnemonic);
		if (useSubstituteMnemonic) {
			isAlias |= true;
			MCInst_setIsAlias(MI, isAlias);

			printOperand(MI, 0, O);
			SStream_concat0(O, ", ");
			printOperand(MI, 1, O);
			SStream_concat(O, "%s", ", ");
			printUInt32(O, (unsigned int)SH);
			PPC_insert_detail_op_imm_at(MI, 2, SH, CS_AC_READ);

			if (useAliasDetails)
				return;
		}
	}

	if (MCInst_getOpcode(MI) == PPC_RLDICR ||
	    MCInst_getOpcode(MI) == PPC_RLDICR_32) {
		unsigned char SH = MCOperand_getImm(MCInst_getOperand(MI, (2)));
		unsigned char ME = MCOperand_getImm(MCInst_getOperand(MI, (3)));

		useAliasDetails |= map_use_alias_details(MI);
		map_set_fill_detail_ops(MI, useAliasDetails && 63 - SH == ME);
		// rldicr RA, RS, SH, 63-SH == sldi RA, RS, SH
		if (63 - SH == ME) {
			isAlias |= true;
			MCInst_setIsAlias(MI, isAlias);
			SStream_concat0(O, "sldi ");
			printOperand(MI, 0, O);
			SStream_concat0(O, ", ");
			printOperand(MI, 1, O);
			SStream_concat(O, "%s", ", ");
			printUInt32(O, (unsigned int)SH);
			PPC_insert_detail_op_imm_at(MI, 2, SH, CS_AC_READ);

			if (useAliasDetails)
				return;
		}
	}

	// dcbt[st] is printed manually here because:
	//  1. The assembly syntax is different between embedded and server targets
	//  2. We must print the short mnemonics for TH == 0 because the
	//     embedded/server syntax default will not be stable across assemblers
	//  The syntax for dcbt is:
	//    dcbt ra, rb, th [server]
	//    dcbt th, ra, rb [embedded]
	//  where th can be omitted when it is 0. dcbtst is the same.
	// On AIX, only emit the extended mnemonics for dcbt and dcbtst if
	// the "modern assembler" is available.
	if ((MCInst_getOpcode(MI) == PPC_DCBT ||
	     MCInst_getOpcode(MI) == PPC_DCBTST) &&
	    (!PPC_getFeatureBits(MI->csh->mode, PPC_FeatureModernAIXAs))) {
		unsigned char TH = MCOperand_getImm(MCInst_getOperand(MI, (0)));
		SStream_concat0(O, "dcbt");
		if (MCInst_getOpcode(MI) == PPC_DCBTST)
			SStream_concat0(O, "st");
		if (TH == 16)
			SStream_concat0(O, "t");
		SStream_concat0(O, " ");

		bool IsBookE =
			PPC_getFeatureBits(MI->csh->mode, PPC_FeatureBookE);
		if (IsBookE && TH != 0 && TH != 16) {
			printUInt32(O, (unsigned int)TH);
			SStream_concat0(O, ", ");
			PPC_set_detail_op_imm(MI, 0, TH);
		}
		set_mem_access(MI, true);
		printOperand(MI, 1, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 2, O);
		set_mem_access(MI, false);

		if (!IsBookE && TH != 0 && TH != 16) {
			SStream_concat(O, "%s", ", ");
			printUInt32(O, (unsigned int)TH);
			PPC_set_detail_op_imm(MI, 0, TH);
		}

		return;
	}

	if (MCInst_getOpcode(MI) == PPC_DCBF) {
		unsigned char L = MCOperand_getImm(MCInst_getOperand(MI, (0)));
		if (!L || L == 1 || L == 3 || L == 4 || L == 6) {
			SStream_concat0(O, "dcb");
			if (L != 6)
				SStream_concat0(O, "f");
			if (L == 1)
				SStream_concat0(O, "l");
			if (L == 3)
				SStream_concat0(O, "lp");
			if (L == 4)
				SStream_concat0(O, "ps");
			if (L == 6)
				SStream_concat0(O, "stps");
			SStream_concat0(O, " ");

			printOperand(MI, 1, O);
			SStream_concat0(O, ", ");
			printOperand(MI, 2, O);

			return;
		}
	}

	// isAlias/useAliasDetails could have been set before.
	useAliasDetails |= map_use_alias_details(MI);
	map_set_fill_detail_ops(MI, useAliasDetails);
	isAlias |= printAliasInstr(MI, Address, O);
	MCInst_setIsAlias(MI, isAlias);

	if (!isAlias || !useAliasDetails) {
		map_set_fill_detail_ops(MI, true);
		if (isAlias)
			SStream_Close(O);
		printInstruction(MI, Address, O);
		if (isAlias)
			SStream_Open(O);
	}
}

const char *PPC_LLVM_getRegisterName(unsigned RegNo)
{
	return getRegisterName(RegNo);
}

void PPC_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			SStream *O)
{
	printInst(MI, Address, Annot, O);
}
