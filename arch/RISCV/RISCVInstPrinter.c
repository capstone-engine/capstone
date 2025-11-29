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

#include <capstone/platform.h>
#include "../../MathExtras.h"

#include "RISCVMapping.h"
#include "RISCVInstPrinter.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "RISCVGenRegisterInfo.inc"

#define GET_SysRegsList_IMPL
#include "RISCVGenSystemOperands.inc"

#define GEN_UNCOMPRESS_INSTR
#include "RISCVGenCompressedInstructionsInfo.inc"

#include "RISCVMapping.h"
#include "../../Mapping.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

static void printCustomAliasOperand(MCInst *MI, uint64_t Address,
				    unsigned OpIdx, unsigned PrintMethodIdx,
				    SStream *OS);
static inline void printRegName(SStream *O, MCRegister Reg);
static inline void printOperand(MCInst *MI, unsigned OpNo, SStream *O);
// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#include "RISCVGenAsmWriter.inc"

// Print architectural register names rather than the ABI names (such as x2
// instead of sp).
// TODO: Make RISCVInstPrinter_doGetRegisterName non-static so that this can a
// member.
static bool ArchRegNames;

const char *doGetRegisterName(MCRegister Reg)
{
	return getRegisterName(Reg, ArchRegNames ? RISCV_NoRegAltName :
						   RISCV_ABIRegAltName);
}

static inline void printRegName(SStream *O, MCRegister Reg)
{
	SStream_concat0(markup_OS(O, Markup_Register), doGetRegisterName(Reg));
}

bool haveRequiredFeatures(const RISCV_SysReg *Reg, MCInst *MI)
{
	// Not in 32-bit mode.
	if (Reg->isRV32Only &&
	    RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit))
		return false;

	return true;
}

static inline void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Operand, OpNo);

	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	if (MCOperand_isReg(MO)) {
		printRegName(O, MCOperand_getReg(MO));
		return;
	}

	if (MCOperand_isImm(MO)) {
		printInt64(markup_OS(O, Markup_Immediate),
			   MCOperand_getImm(MO));
		return;
	}

	CS_ASSERT(MCOperand_isExpr(MO) &&
		  "Unknown operand kind in printOperand");
	printExpr(O, MCOperand_getExpr(MO));
}

void printBranchOperand(MCInst *MI, uint64_t Address, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_BranchOperand, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));
	if (!MCOperand_isImm(MO))
		return printOperand(MI, OpNo, O);

	if (MI->csh->PrintBranchImmAsAddress) {
		uint64_t Target = Address + MCOperand_getImm(MO);
		if (!RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit))
			Target &= 0xffffffff;
		printUInt64(markup_OS(O, Markup_Target), Target);
	} else {
		printInt64(markup_OS(O, Markup_Target), MCOperand_getImm(MO));
	}
}

void printCSRSystemRegister(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_CSRSystemRegister, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	const RISCV_SysReg *SysReg = RISCV_lookupSysRegByEncoding(Imm);
	if (SysReg && haveRequiredFeatures(SysReg, MI))
		SStream_concat0(markup_OS(O, Markup_Register), SysReg->Name);
	else
		printUInt64(markup_OS(O, Markup_Register), Imm);
}

void printFenceArg(MCInst *MI, unsigned OpNo, SStream *O)
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

void printFRMArg(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FRMArg, OpNo);
	unsigned FRMArg = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	if (!(MI->csh->syntax & CS_OPT_SYNTAX_NO_ALIAS_TEXT) &&
	    FRMArg == RISCVFPRndMode_DYN)
		return;
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, RISCVFPRndMode_roundingModeToString(FRMArg));
}

void printFRMArgLegacy(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FRMArgLegacy, OpNo);
	unsigned FRMArg = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	// Never print rounding mode if it's the default 'rne'. This ensures the
	// output can still be parsed by older tools that erroneously failed to
	// accept a rounding mode.
	if (FRMArg == RISCVFPRndMode_RNE)
		return;
	SStream_concat(O, "%s", ", ");
	SStream_concat0(O, RISCVFPRndMode_roundingModeToString(FRMArg));
}

void printFPImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_FPImmOperand, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	if (Imm == 1) {
		SStream_concat0(markup_OS(O, Markup_Immediate), "min");
	} else if (Imm == 30) {
		SStream_concat0(markup_OS(O, Markup_Immediate), "inf");
	} else if (Imm == 31) {
		SStream_concat0(markup_OS(O, Markup_Immediate), "nan");
	} else {
		float FPVal = getFPImm(Imm);
		// If the value is an integer, print a .0 fraction. Otherwise, use %g to
		// which will not print trailing zeros and will use scientific notation
		// if it is shorter than printing as a decimal. The smallest value requires
		// 12 digits of precision including the decimal.
		if (FPVal == (int)(FPVal))
			printfFloat(markup_OS(O, Markup_Immediate), "%.1f",
				    FPVal);
		else
			printfFloat(markup_OS(O, Markup_Immediate), "%.12g",
				    FPVal);
	}
}

void printZeroOffsetMemOp(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_ZeroOffsetMemOp, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	CS_ASSERT(MCOperand_isReg(MO) &&
		  "printZeroOffsetMemOp can only print register operands");
	SStream_concat0(O, "(");
	printRegName(O, MCOperand_getReg(MO));
	SStream_concat0(O, ")");
}

void printVTypeI(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_VTypeI, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	// Print the raw immediate for reserved values: vlmul[2:0]=4, vsew[2:0]=0b1xx,
	// or non-zero in bits 8 and above.
	if (RISCVVType_getVLMUL(Imm) == RISCVII_LMUL_RESERVED ||
	    RISCVVType_getSEW(Imm) > 64 || (Imm >> 8) != 0) {
		printUInt64(O, Imm);
		return;
	}
	// Print the text form.
	printVType(Imm, O);
}

void printRlist(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Rlist, OpNo);
	unsigned Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	SStream_concat0(O, "{");
	switch (Imm) {
	case RISCVZC_RLISTENCODE_RA:
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		break;
	case RISCVZC_RLISTENCODE_RA_S0:
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		break;
	case RISCVZC_RLISTENCODE_RA_S0_S1:
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x9" : "s1"));
		break;
	case RISCVZC_RLISTENCODE_RA_S0_S2:
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x9" : "s2"));
		if (ArchRegNames) {
			SStream_concat0(O, ", ");
			SStream_concat0(markup_OS(O, Markup_Register), "x18");
		}
		break;
	case RISCVZC_RLISTENCODE_RA_S0_S3:
	case RISCVZC_RLISTENCODE_RA_S0_S4:
	case RISCVZC_RLISTENCODE_RA_S0_S5:
	case RISCVZC_RLISTENCODE_RA_S0_S6:
	case RISCVZC_RLISTENCODE_RA_S0_S7:
	case RISCVZC_RLISTENCODE_RA_S0_S8:
	case RISCVZC_RLISTENCODE_RA_S0_S9:
	case RISCVZC_RLISTENCODE_RA_S0_S11:
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x1" : "ra"));
		SStream_concat0(O, ", ");
		SStream_concat0(markup_OS(O, Markup_Register),
				(ArchRegNames ? "x8" : "s0"));
		SStream_concat0(O, "-");

		if (ArchRegNames) {
			SStream_concat0(markup_OS(O, Markup_Register), "x9");
			SStream_concat0(O, ", ");
			SStream_concat0(markup_OS(O, Markup_Register), "x18");
			SStream_concat0(O, "-");
		}
		SStream_concat0(
			markup_OS(O, Markup_Register),
			doGetRegisterName(
				RISCV_X19 +
				(Imm == RISCVZC_RLISTENCODE_RA_S0_S11 ?
					 8 :
					 Imm - RISCVZC_RLISTENCODE_RA_S0_S3)));
		break;
	default:
		CS_ASSERT(0 && "invalid register list");
	}
	SStream_concat0(O, "}");
}

void printRegReg(MCInst *MI, unsigned OpNo, SStream *O)
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

void printSpimm(MCInst *MI, unsigned OpNo, SStream *O)
{
	RISCV_add_cs_detail_0(MI, RISCV_OP_GROUP_Spimm, OpNo);
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, (OpNo)));
	unsigned Opcode = MCInst_getOpcode(MI);
	bool IsRV64 = RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit);
	bool IsEABI = RISCV_getFeatureBits(MI->csh->mode, RISCV_FeatureRVE);
	int64_t Spimm = 0;
	int64_t RlistVal = MCOperand_getImm(MCInst_getOperand(MI, (0)));
	CS_ASSERT(RlistVal != 16 && "Incorrect rlist.");
	unsigned Base = RISCVZC_getStackAdjBase(RlistVal, IsRV64, IsEABI);
	Spimm = Imm + Base;
	CS_ASSERT((Spimm >= Base && Spimm <= Base + 48) && "Incorrect spimm");
	if (Opcode == RISCV_CM_PUSH)
		Spimm = -Spimm;

	RISCVZC_printSpimm(Spimm, markup_OS(O, Markup_Immediate));
}

void printVMaskReg(MCInst *MI, unsigned OpNo, SStream *O)
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

void RISCV_LLVM_printInstruction(MCInst *MI, SStream *O,
				 void * /* MCRegisterInfo* */ info)
{
	MI->MRI = (MCRegisterInfo *)info;

	MCInst_setIsAlias(MI, false);
	// print the exact instruction text and done
	if (MI->csh->syntax & CS_OPT_SYNTAX_NO_ALIAS_TEXT) {
		printInstruction(MI, MI->address, O);
	} else {
		/* the instruction might be an alias, including in the case of a compressed instruction */
		MCInst Uncompressed;
		MCInst_Init(&Uncompressed, MI->csh->arch);

		MCInst *McInstr = MI;
		if (uncompressInst(&Uncompressed, MI)) {
			McInstr = &Uncompressed;
			Uncompressed.address = MI->address;
			Uncompressed.MRI = MI->MRI;
			Uncompressed.csh = MI->csh;
			Uncompressed.flat_insn = MI->flat_insn;
		}

		if (printAliasInstr(McInstr, MI->address, O)) {
			MCInst_setIsAlias(MI, true);
			if (!map_use_alias_details(MI) && detail_is_set(MI)) {
				// disable actual printing
				SStream_Close(O);
				memset(MI->flat_insn->detail->riscv.operands, 0,
				       sizeof(MI->flat_insn->detail->riscv
						      .operands));
				MI->flat_insn->detail->riscv.op_count = 0;
				// re-disassemble again in order to obtain the full details
				// including the whole operands array
				printInstruction(MI, MI->address, O);
				// re-open the stream to restore the usual state
				SStream_Open(O);
			}
		} else
			printInstruction(McInstr, MI->address, O);
	}
	RISCV_add_groups(MI);
	RISCV_add_missing_write_access(MI);
	RISCV_compact_operands(MI);
}

const char *getSysRegName(unsigned reg)
{
	const RISCV_SysReg *SysReg = RISCV_lookupSysRegByEncoding(reg);
	return SysReg->Name;
}

const char *RISCV_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}

bool isCompressed(MCInst *MI)
{
	MCInst unused;
	MCInst_Init(&unused, MI->csh->arch);
	return uncompressInst(&unused, MI);
}
