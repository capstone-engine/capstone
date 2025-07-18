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

//===-- RISCVInstPrinter.cpp - Convert RISC-V MCInst to asm syntax --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an RISC-V MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "RISCVMapping.h"
#include "RISCVInstPrinter.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "RISCVGenRegisterInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#include "RISCVGenAsmWriter.inc"

// Print architectural register names rather than the ABI names (such as x2
// instead of sp).
// TODO: Make RISCVInstPrinter::getRegisterName non-static so that this can a
// member.
static bool ArchRegNames;

void printRegName(SStream *O, MCRegister Reg)
{
	SStream_concat0(markup(O, Markup_Register), getRegisterName(Reg));
}

static inline void printOperand(MCInst *MI, unsigned OpNo, SStream *O,
				const char *Modifier)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Operand, OpNo);
	CS_ASSERT((Modifier == nullptr || Modifier[0] == 0) &&
		  "No modifiers supported");
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	if (MCOperand_isReg(MO)) {
		printRegName(O, MCOperand_getReg(MO));
		return;
	}

	if (MCOperand_isImm(MO)) {
		SStream_concat0(markup(O, Markup_Immediate),
				formatImm(MCOperand_getImm(MO)));
		return;
	}

	CS_ASSERT(MCOperand_isExpr(MO) &&
		  "Unknown operand kind in printOperand");
	MCOperand_getExpr(MO)->print(O, &MAI);
}

static inline void printBranchOperand(MCInst *MI, uint64_t Address,
				      unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_BranchOperand, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));
	if (!MCOperand_isImm(MO))
		return printOperand(MI, OpNo, O);

	if (PrintBranchImmAsAddress) {
		uint64_t Target = Address + MCOperand_getImm(MO);
		if (!STI.hasFeature(RISCV_Feature64Bit))
			Target &= 0xffffffff;
		SStream_concat0(markup(O, Markup_Target), formatHex(Target));
	} else {
		SStream_concat0(markup(O, Markup_Target),
				formatImm(MCOperand_getImm(MO)));
	}
}

static inline void printCSRSystemRegister(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_CSRSystemRegister, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	auto SysReg = RISCVSysReg_lookupSysRegByEncoding(Imm);
	if (SysReg && SysReg->haveRequiredFeatures(STI.getFeatureBits()))
		SStream_concat0(markup(O, Markup_Register), SysReg->Name);
	else
		SStream_concat0(markup(O, Markup_Register), formatImm(Imm));
}

static inline void printFenceArg(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FenceArg, OpNo);
	unsigned FenceArg = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	CS_ASSERT(((FenceArg >> 4) == 0) &&
		  "Invalid immediate in printFenceArg");

	if ((FenceArg & RISCVFenceField_I) != 0)
		SStream_concat0(O, "i");

	if ((FenceArg & RISCVFenceField_O) != 0)
		SStream_concat0(O, "o");

	if ((FenceArg & RISCVFenceField_R) != 0)
		SStream_concat0(O, "r");

	if ((FenceArg & RISCVFenceField_W) != 0)
		SStream_concat0(O, "w");

	if (FenceArg == 0)
		SStream_concat0(O, "0");
}

static inline void printFRMArg(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FRMArg, OpNo);
	auto FRMArg = (RISCVFPRndMode_RoundingMode)(MCOperand_getImm(
		MCInst_getOperand(MI, (OpNo))));
	if (PrintAliases && !NoAliases &&
	    FRMArg == RISCVFPRndMode_RoundingMode::DYN)
		return;
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, RISCVFPRndMode_roundingModeToString(FRMArg));
}

static inline void printFRMArgLegacy(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FRMArgLegacy, OpNo);
	auto FRMArg = (RISCVFPRndMode_RoundingMode)(MCOperand_getImm(
		MCInst_getOperand(MI, (OpNo))));
	// Never print rounding mode if it's the default 'rne'. This ensures the
	// output can still be parsed by older tools that erroneously failed to
	// accept a rounding mode.
	if (FRMArg == RISCVFPRndMode_RoundingMode::RNE)
		return;
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, RISCVFPRndMode_roundingModeToString(FRMArg));
}

static inline void printFPImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FPImmOperand, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	if (Imm == 1) {
		SStream_concat0(markup(O, Markup_Immediate), "min");
	} else if (Imm == 30) {
		SStream_concat0(markup(O, Markup_Immediate), "inf");
	} else if (Imm == 31) {
		SStream_concat0(markup(O, Markup_Immediate), "nan");
	} else {
		float FPVal = RISCVLoadFPImm_getFPImm(Imm);
		// If the value is an integer, print a .0 fraction. Otherwise, use %g to
		// which will not print trailing zeros and will use scientific notation
		// if it is shorter than printing as a decimal. The smallest value requires
		// 12 digits of precision including the decimal.
		if (FPVal == (int)(FPVal))
			SStream_concat0(markup(O, Markup_Immediate),
					format("%.1f", FPVal));
		else
			SStream_concat0(markup(O, Markup_Immediate),
					format("%.12g", FPVal));
	}
}

static inline void printZeroOffsetMemOp(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_ZeroOffsetMemOp, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	CS_ASSERT(MCOperand_isReg(MO) &&
		  "printZeroOffsetMemOp can only print register operands");
	SStream_concat0(O, "(");
	printRegName(O, MCOperand_getReg(MO));
	SStream_concat0(O, ")");
}

static inline void printVTypeI(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_VTypeI, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	// Print the raw immediate for reserved values: vlmul[2:0]=4, vsew[2:0]=0b1xx,
	// or non-zero in bits 8 and above.
	if (RISCVVType_getVLMUL(Imm) == RISCVII_VLMUL::LMUL_RESERVED ||
	    RISCVVType_getSEW(Imm) > 64 || (Imm >> 8) != 0) {
		SStream_concat0(O, formatImm(Imm));
		return;
	}
	// Print the text form.
	RISCVVType_printVType(Imm, O);
}

static inline void printRlist(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Rlist, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	SStream_concat0(O, "{");
	switch (Imm) {
	case RISCVZC_RLISTENCODE::RA:
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		break;
	case RISCVZC_RLISTENCODE::RA_S0:
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		break;
	case RISCVZC_RLISTENCODE::RA_S0_S1:
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x9" : "s1"));
		break;
	case RISCVZC_RLISTENCODE::RA_S0_S2:
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x9" : "s2"));
		if (ArchRegNames) {
			SStream_concat0(O, ", ");
			SStream_concat0(markup(O, Markup_Register), "x18");
		}
		break;
	case RISCVZC_RLISTENCODE::RA_S0_S3:
	case RISCVZC_RLISTENCODE::RA_S0_S4:
	case RISCVZC_RLISTENCODE::RA_S0_S5:
	case RISCVZC_RLISTENCODE::RA_S0_S6:
	case RISCVZC_RLISTENCODE::RA_S0_S7:
	case RISCVZC_RLISTENCODE::RA_S0_S8:
	case RISCVZC_RLISTENCODE::RA_S0_S9:
	case RISCVZC_RLISTENCODE::RA_S0_S11:
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		if (ArchRegNames) {
			SStream_concat0(markup(O, Markup_Register), "x9");
			SStream_concat0(O, ", ");
			SStream_concat0(markup(O, Markup_Register), "x18");
			SStream_concat0(O, "-");
		}
		SStream_concat0(
			markup(O, Markup_Register),
			getRegisterName(
				RISCV_X19 +
				(Imm == RISCVZC_RLISTENCODE::RA_S0_S11 ?
					 8 :
					 Imm - RISCVZC_RLISTENCODE::RA_S0_S3)));
		break;
	default:
		CS_ASSERT(0 && "invalid register list");
	}
	SStream_concat0(O, "}");
}

static inline void printRegReg(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_RegReg, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	CS_ASSERT(MCOperand_isReg(MO) &&
		  "printRegReg can only print register operands");
	if (MCOperand_getReg(MO) == RISCV_NoRegister)
		return;
	printRegName(O, MCOperand_getReg(MO));

	SStream_concat0(O, "(");
	MCOperand *MO1 = MCInst_getOperand(MI, (OpNo + 1));
	CS_ASSERT(MCOperand_isReg(MO1) &&
		  "printRegReg can only print register operands");
	printRegName(O, MCOperand_getReg(MO1));
	SStream_concat0(O, ")");
}

static inline void printSpimm(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Spimm, OpNo);
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	unsigned Opcode = MCInst_getOpcode(MI);
	bool IsRV64 = STI.hasFeature(RISCV_Feature64Bit);
	bool IsEABI = STI.hasFeature(RISCV_FeatureRVE);
	int64_t Spimm = 0;
	auto RlistVal = MCOperand_getImm(MCInst_getOperand(MI, (0)));
	CS_ASSERT(RlistVal != 16 && "Incorrect rlist.");
	auto Base = RISCVZC_getStackAdjBase(RlistVal, IsRV64, IsEABI);
	Spimm = Imm + Base;
	CS_ASSERT((Spimm >= Base && Spimm <= Base + 48) && "Incorrect spimm");
	if (Opcode == RISCV_CM_PUSH)
		Spimm = -Spimm;

	// RAII guard for ANSI color escape sequences
	WithMarkup ScopedMarkup = markup(O, Markup_Immediate);
	RISCVZC_printSpimm(Spimm, O);
}

static inline void printVMaskReg(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_VMaskReg, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	CS_ASSERT(MCOperand_isReg(MO) &&
		  "printVMaskReg can only print register operands");
	if (MCOperand_getReg(MO) == RISCV_NoRegister)
		return;
	SStream_concat0(O, ", ");
	printRegName(O, MCOperand_getReg(MO));
	SStream_concat0(O, ".t");
}

const char *getRegisterName(MCRegister Reg)
{
	return getRegisterName(Reg, ArchRegNames ? RISCV_NoRegAltName :
						   RISCV_ABIRegAltName);
}
