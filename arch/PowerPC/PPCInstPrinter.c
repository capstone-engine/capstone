//===-- PPCInstPrinter.cpp - Convert PPC MCInst to assembly syntax --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an PPC MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PPCInstPrinter.h"
#include "PPCPredicates.h"
#include "../../MCInst.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "PPCMapping.h"

#ifndef CAPSTONE_DIET
static char *getRegisterName(unsigned RegNo);
#endif

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);
static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI);
static void printAbsBranchOperand(MCInst *MI, unsigned OpNo, SStream *O);
static char *printAliasInstr(MCInst *MI, SStream *OS, void *info);
static char *printAliasInstrEx(MCInst *MI, SStream *OS, void *info);
static void printCustomAliasOperand(MCInst *MI, unsigned OpIdx,
		unsigned PrintMethodIdx, SStream *OS);

static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->csh->detail != CS_OPT_ON)
		return;

	MI->csh->doing_mem = status;

	if (status) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_MEM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].mem.base = PPC_REG_INVALID;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].mem.disp = 0;
	} else {
		// done, create the next operand slot
		MI->flat_insn->detail->ppc.op_count++;
	}
}

void PPC_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci)
{
	if (((cs_struct *)ud)->detail != CS_OPT_ON)
		return;

	// check if this insn has branch hint
	if (strrchr(insn_asm, '+') != NULL && !strstr(insn_asm, ".+")) {
		insn->detail->ppc.bh = PPC_BH_PLUS;
	} else if (strrchr(insn_asm, '-') != NULL) {
		insn->detail->ppc.bh = PPC_BH_MINUS;
	}
}

#define GET_INSTRINFO_ENUM
#include "PPCGenInstrInfo.inc"

void PPC_printInst(MCInst *MI, SStream *O, void *Info)
{
	char *mnem;

	// Check for slwi/srwi mnemonics.
	if (MCInst_getOpcode(MI) == PPC_RLWINM) {
		unsigned char SH = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 2));
		unsigned char MB = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 3));
		unsigned char ME = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 4));
		bool useSubstituteMnemonic = false;

		if (SH <= 31 && MB == 0 && ME == (31-SH)) {
			SStream_concat0(O, "slwi\t");
			MCInst_setOpcodePub(MI, PPC_INS_SLWI);
			useSubstituteMnemonic = true;
		}

		if (SH <= 31 && MB == (32-SH) && ME == 31) {
			SStream_concat0(O, "srwi\t");
			MCInst_setOpcodePub(MI, PPC_INS_SRWI);
			useSubstituteMnemonic = true;
			SH = 32-SH;
		}

		if (useSubstituteMnemonic) {
			printOperand(MI, 0, O);
			SStream_concat0(O, ", ");
			printOperand(MI, 1, O);
			if (SH > HEX_THRESHOLD)
				SStream_concat(O, ", 0x%x", (unsigned int)SH);
			else
				SStream_concat(O, ", %u", (unsigned int)SH);

			return;
		}
	}

	if ((MCInst_getOpcode(MI) == PPC_OR || MCInst_getOpcode(MI) == PPC_OR8) &&
			MCOperand_getReg(MCInst_getOperand(MI, 1)) == MCOperand_getReg(MCInst_getOperand(MI, 1))) {
		SStream_concat0(O, "mr\t");
		MCInst_setOpcodePub(MI, PPC_INS_MR);
		printOperand(MI, 0, O);
		SStream_concat0(O, ", ");
		printOperand(MI, 1, O);
		return;
	}

	if (MCInst_getOpcode(MI) == PPC_RLDICR) {
		unsigned char SH = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 2));
		unsigned char ME = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 3));
		// rldicr RA, RS, SH, 63-SH == sldi RA, RS, SH
		if (63-SH == ME) {
			SStream_concat0(O, "sldi\t");
			MCInst_setOpcodePub(MI, PPC_INS_SLDI);
			printOperand(MI, 0, O);
			SStream_concat0(O, ", ");
			printOperand(MI, 1, O);
			if (SH > HEX_THRESHOLD)
				SStream_concat(O, ", 0x%x", (unsigned int)SH);
			else
				SStream_concat(O, ", %u", (unsigned int)SH);

			return;
		}
	}

	if (MCInst_getOpcode(MI) == PPC_gBC)
	{
		int64_t bd = MCOperand_getImm(MCInst_getOperand(MI, 2));
		bd = SignExtend64(bd, 14);
		MCOperand_setImm(MCInst_getOperand(MI, 2),bd);
	}

	if ((MCInst_getOpcode(MI) == PPC_B)||(MCInst_getOpcode(MI) == PPC_BA)||
			(MCInst_getOpcode(MI) == PPC_BL)||(MCInst_getOpcode(MI) == PPC_BLA))
	{
		int64_t bd = MCOperand_getImm(MCInst_getOperand(MI, 0));
		bd = SignExtend64(bd, 24);
		MCOperand_setImm(MCInst_getOperand(MI, 0),bd);
	}

	// consider our own alias instructions first
	mnem = printAliasInstrEx(MI, O, Info);
	if (!mnem)
		mnem = printAliasInstr(MI, O, Info);

	if (mnem) {
		struct ppc_alias alias;
		// check to remove the last letter of ('.', '-', '+')
		if (mnem[strlen(mnem) - 1] == '-' || mnem[strlen(mnem) - 1] == '+' || mnem[strlen(mnem) - 1] == '.')
			mnem[strlen(mnem) - 1] = '\0';

		if (PPC_alias_insn(mnem, &alias)) {
			MCInst_setOpcodePub(MI, alias.id);
			if (MI->csh->detail) {
				MI->flat_insn->detail->ppc.bc = (ppc_bc)alias.cc;
			}
		}

		cs_mem_free(mnem);
	} else
		printInstruction(MI, O, NULL);
}

enum ppc_bc_hint {
	PPC_BC_LT_MINUS = (0 << 5) | 14,
	PPC_BC_LE_MINUS = (1 << 5) |  6,
	PPC_BC_EQ_MINUS = (2 << 5) | 14,
	PPC_BC_GE_MINUS = (0 << 5) |  6,
	PPC_BC_GT_MINUS = (1 << 5) | 14,
	PPC_BC_NE_MINUS = (2 << 5) |  6,
	PPC_BC_UN_MINUS = (3 << 5) | 14,
	PPC_BC_NU_MINUS = (3 << 5) |  6,
	PPC_BC_LT_PLUS  = (0 << 5) | 15,
	PPC_BC_LE_PLUS  = (1 << 5) |  7,
	PPC_BC_EQ_PLUS  = (2 << 5) | 15,
	PPC_BC_GE_PLUS  = (0 << 5) |  7,
	PPC_BC_GT_PLUS  = (1 << 5) | 15,
	PPC_BC_NE_PLUS  = (2 << 5) |  7,
	PPC_BC_UN_PLUS  = (3 << 5) | 15,
	PPC_BC_NU_PLUS  = (3 << 5) |  7,
};

// normalize CC to remove _MINUS & _PLUS
static int cc_normalize(int cc)
{
	switch(cc) {
		default: return cc;
		case PPC_BC_LT_MINUS: return PPC_BC_LT;
		case PPC_BC_LE_MINUS: return PPC_BC_LE;
		case PPC_BC_EQ_MINUS: return PPC_BC_EQ;
		case PPC_BC_GE_MINUS: return PPC_BC_GE;
		case PPC_BC_GT_MINUS: return PPC_BC_GT;
		case PPC_BC_NE_MINUS: return PPC_BC_NE;
		case PPC_BC_UN_MINUS: return PPC_BC_UN;
		case PPC_BC_NU_MINUS: return PPC_BC_NU;
		case PPC_BC_LT_PLUS : return PPC_BC_LT;
		case PPC_BC_LE_PLUS : return PPC_BC_LE;
		case PPC_BC_EQ_PLUS : return PPC_BC_EQ;
		case PPC_BC_GE_PLUS : return PPC_BC_GE;
		case PPC_BC_GT_PLUS : return PPC_BC_GT;
		case PPC_BC_NE_PLUS : return PPC_BC_NE;
		case PPC_BC_UN_PLUS : return PPC_BC_UN;
		case PPC_BC_NU_PLUS : return PPC_BC_NU;
	}
}

static void printPredicateOperand(MCInst *MI, unsigned OpNo,
		SStream *O, const char *Modifier)
{
	unsigned Code = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));

	MI->flat_insn->detail->ppc.bc = (ppc_bc)cc_normalize(Code);

	if (!strcmp(Modifier, "cc")) {
		switch ((ppc_predicate)Code) {
			default:	// unreachable
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
				// llvm_unreachable("Invalid use of bit predicate code");
				SStream_concat0(O, "invalid-predicate");
				return;
		}
	}

	if (!strcmp(Modifier, "pm")) {
		switch ((ppc_predicate)Code) {
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
				// llvm_unreachable("Invalid use of bit predicate code");
				SStream_concat0(O, "invalid-predicate");
				return;
			default:	// unreachable
				return;
		}
		// llvm_unreachable("Invalid predicate code");
	}

	//assert(StringRef(Modifier) == "reg" &&
	//		"Need to specify 'cc', 'pm' or 'reg' as predicate op modifier!");
	printOperand(MI, OpNo + 1, O);
}

static void printU2ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned int Value = (int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
	//assert(Value <= 3 && "Invalid u2imm argument!");

	if (Value > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", Value);
	else
		SStream_concat(O, "%u", Value);

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Value;
		MI->flat_insn->detail->ppc.op_count++;
	}
}

static void printU4ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned int Value = (int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
	//assert(Value <= 15 && "Invalid u4imm argument!");

	if (Value > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", Value);
	else
		SStream_concat(O, "%u", Value);

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Value;
		MI->flat_insn->detail->ppc.op_count++;
	}
}

static void printS5ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	int Value = (int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
	Value = SignExtend32(Value, 5);

	if (Value >= 0) {
		if (Value > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", Value);
		else
			SStream_concat(O, "%u", Value);
	} else {
		if (Value < -HEX_THRESHOLD)
			SStream_concat(O, "-0x%x", -Value);
		else
			SStream_concat(O, "-%u", -Value);
	}

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Value;
		MI->flat_insn->detail->ppc.op_count++;
	}
}

static void printU5ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned int Value = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
	//assert(Value <= 31 && "Invalid u5imm argument!");
	if (Value > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", Value);
	else
		SStream_concat(O, "%u", Value);

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Value;
		MI->flat_insn->detail->ppc.op_count++;
	}
}

static void printU6ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned int Value = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
	//assert(Value <= 63 && "Invalid u6imm argument!");
	if (Value > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", Value);
	else
		SStream_concat(O, "%u", Value);

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Value;
		MI->flat_insn->detail->ppc.op_count++;
	}
}

static void printS16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		short Imm = (short)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", Imm);
			else
				SStream_concat(O, "%u", Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -Imm);
			else
				SStream_concat(O, "-%u", -Imm);
		}

		if (MI->csh->detail) {
			MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
			MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Imm;
			MI->flat_insn->detail->ppc.op_count++;
		}
	} else
		printOperand(MI, OpNo, O);
}

static void printS16ImmOperand_Mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		short Imm = (short)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		// Do not print zero offset
		if (Imm == 0)
			return;

		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", Imm);
			else
				SStream_concat(O, "%u", Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -Imm);
			else
				SStream_concat(O, "-%u", -Imm);
		}

		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].mem.disp = Imm;
			} else {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Imm;
				MI->flat_insn->detail->ppc.op_count++;
			}
		}
	} else
		printOperand(MI, OpNo, O);
}

static void printU16ImmOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		unsigned short Imm = (unsigned short)MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		if (Imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", Imm);
		else
			SStream_concat(O, "%u", Imm);

		if (MI->csh->detail) {
			MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
			MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = Imm;
			MI->flat_insn->detail->ppc.op_count++;
		}
	} else
		printOperand(MI, OpNo, O);
}

static void printBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (!MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		printOperand(MI, OpNo, O);
		return;
	}

	// Branches can take an immediate operand.  This is used by the branch
	// selection pass to print .+8, an eight byte displacement from the PC.
	//SStream_concat0(O, ".+");
	printAbsBranchOperand(MI, OpNo, O);
}

static void printAbsBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	int imm;
	if (!MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		printOperand(MI, OpNo, O);
		return;
	}

	imm = ((int)MCOperand_getImm(MCInst_getOperand(MI, OpNo)) << 2);
	if (imm >= 0) {
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, ".+0x%x", imm);
		else
			SStream_concat(O, ".+%u", imm);
	} else {
		if (imm < -HEX_THRESHOLD)
			SStream_concat(O, ".-0x%x", -imm);
		else
			SStream_concat(O, ".-%u", -imm);
	}

	if (MI->csh->detail) {
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
		MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = imm;
		MI->flat_insn->detail->ppc.op_count++;
	}
}


#define GET_REGINFO_ENUM
#include "PPCGenRegisterInfo.inc"

static void printcrbitm(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned CCReg = MCOperand_getReg(MCInst_getOperand(MI, OpNo));
	unsigned RegNo, tmp;
	switch (CCReg) {
		default: // llvm_unreachable("Unknown CR register");
		case PPC_CR0: RegNo = 0; break;
		case PPC_CR1: RegNo = 1; break;
		case PPC_CR2: RegNo = 2; break;
		case PPC_CR3: RegNo = 3; break;
		case PPC_CR4: RegNo = 4; break;
		case PPC_CR5: RegNo = 5; break;
		case PPC_CR6: RegNo = 6; break;
		case PPC_CR7: RegNo = 7; break;
	}

	tmp = 0x80 >> RegNo;
	if (tmp > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", tmp);
	else
		SStream_concat(O, "%u", tmp);
}

static void printMemRegImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);

	printS16ImmOperand_Mem(MI, OpNo, O);

	SStream_concat0(O, "(");

	if (MCOperand_getReg(MCInst_getOperand(MI, OpNo + 1)) == PPC_R0)
		SStream_concat0(O, "0");
	else
		printOperand(MI, OpNo + 1, O);

	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printMemRegReg(MCInst *MI, unsigned OpNo, SStream *O)
{
	// When used as the base register, r0 reads constant zero rather than
	// the value contained in the register.  For this reason, the darwin
	// assembler requires that we print r0 as 0 (no r) when used as the base.
	if (MCOperand_getReg(MCInst_getOperand(MI, OpNo)) == PPC_R0)
		SStream_concat0(O, "0");
	else
		printOperand(MI, OpNo, O);
	SStream_concat0(O, ", ");

	printOperand(MI, OpNo + 1, O);
}

static void printTLSCall(MCInst *MI, unsigned OpNo, SStream *O)
{
	set_mem_access(MI, true);
	//printBranchOperand(MI, OpNo, O);

	// On PPC64, VariantKind is VK_None, but on PPC32, it's VK_PLT, and it must
	// come at the _end_ of the expression.
	// MCOperand *Op;
	// Op = MCInst_getOperand(MI, OpNo);
	//const MCSymbolRefExpr &refExp = cast<MCSymbolRefExpr>(*Op.getExpr());
	//O << refExp.getSymbol().getName();

	SStream_concat0(O, "(");
	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);

	//if (refExp.getKind() != MCSymbolRefExpr::VK_None)
	//	O << '@' << MCSymbolRefExpr::getVariantKindName(refExp.getKind());
}

#ifndef CAPSTONE_DIET
/// stripRegisterPrefix - This method strips the character prefix from a
/// register name so that only the number is left.  Used by for linux asm.
static char *stripRegisterPrefix(char *RegName)
{
	switch (RegName[0]) {
		case 'r':
		case 'f':
		case 'v':
			if (RegName[1] == 's')
				return RegName + 2;
			return RegName + 1;
		case 'c':
			if (RegName[1] == 'r')
				return RegName + 2;
	}

	return RegName;
}
#endif

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		unsigned reg = MCOperand_getReg(Op);
#ifndef CAPSTONE_DIET
		char *RegName = getRegisterName(reg);
#endif
		// map to public register
		reg = PPC_map_register(reg);
#ifndef CAPSTONE_DIET
		// The linux and AIX assembler does not take register prefixes.
		if (MI->csh->syntax == CS_OPT_SYNTAX_NOREGNAME)
			RegName = stripRegisterPrefix(RegName);

		SStream_concat0(O, RegName);
#endif

		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].mem.base = reg;
			} else {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_REG;
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].reg = reg;
				MI->flat_insn->detail->ppc.op_count++;
			}
		}

		return;
	}

	if (MCOperand_isImm(Op)) {
		int32_t imm = (int32_t)MCOperand_getImm(Op);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", imm);
			else
				SStream_concat(O, "%u", imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -imm);
			else
				SStream_concat(O, "-%u", -imm);
		}

		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].mem.disp = imm;
			} else {
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].type = PPC_OP_IMM;
				MI->flat_insn->detail->ppc.operands[MI->flat_insn->detail->ppc.op_count].imm = imm;
				MI->flat_insn->detail->ppc.op_count++;
			}
		}
	}
}

static void op_addImm(MCInst *MI, int v)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].type = ARM_OP_IMM;
		MI->flat_insn->detail->arm.operands[MI->flat_insn->detail->arm.op_count].imm = v;
		MI->flat_insn->detail->arm.op_count++;
	}
}

static char *printAliasInstrEx(MCInst *MI, SStream *OS, void *info)
{
#define GETREGCLASS_CONTAIN(_class, _reg) MCRegisterClass_contains(MCRegisterInfo_getRegClass(MRI, _class), MCOperand_getReg(MCInst_getOperand(MI, _reg)))
	const char *AsmString;
	char *tmp, *AsmMnem, *AsmOps, *c;
	int OpIdx, PrintMethodIdx;
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	switch (MCInst_getOpcode(MI)) {
		default: return NULL;
		case PPC_gBC:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 12, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blt $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgt $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beq $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bso $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bt $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 4, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bge $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "ble $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bne $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bns $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bf $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }

				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 14, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blt- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgt- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beq- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bso- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bt- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 6, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bge- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "ble- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bne- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bns- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bf- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 15, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blt+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgt+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beq+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bso+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bt+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBC 7, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bge+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "ble+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bne+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bns+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bf+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCA:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 12, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blta $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgta $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqa $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoa $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bta $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 4, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgea $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blea $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnea $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsa $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfa $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 14, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blta- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgta- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqa- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoa- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bta- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 6, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgea- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blea- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnea- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsa- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfa- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 15, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "blta+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgta+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqa+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoa+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bta+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCA 7, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgea+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blea+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnea+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsa+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfa+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCCTR:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 12, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctr";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctr";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctr";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctr";
							 break;
						 default:
							 AsmString = "btctr $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 4, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectr";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectr";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectr";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctr";
							 break;
						 default:
							 AsmString = "bfctr $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 14, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctr-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctr-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctr-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctr-";
							 break;
						 default:
							 AsmString = "btctr- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 6, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectr-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectr-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectr-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctr-";
							 break;
						 default:
							 AsmString = "bfctr- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 15, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctr+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctr+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctr+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctr+";
							 break;
						 default:
							 AsmString = "btctr+ $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTR 7, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectr+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectr+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectr+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctr+";
							 break;
						 default:
							 AsmString = "bfctr+ $\x02";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCCTRL:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 12, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctrl";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctrl";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctrl";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctrl";
							 break;
						 default:
							 AsmString = "btctrl $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 4, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectrl";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectrl";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectrl";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctrl";
							 break;
						 default:
							 AsmString = "bfctrl $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 14, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctrl-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctrl-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctrl-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctrl-";
							 break;
						 default:
							 AsmString = "btctrl- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 6, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectrl-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectrl-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectrl-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctrl-";
							 break;
						 default:
							 AsmString = "bfctrl- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 15, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltctrl+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtctrl+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqctrl+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsoctrl+";
							 break;
						 default:
							 AsmString = "btctrl+ $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCCTRL 7, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgectrl+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blectrl+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnectrl+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsctrl+";
							 break;
						 default:
							 AsmString = "bfctrl+ $\x02";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCL:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 12, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltl $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtl $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beql $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsol $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btl $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 4, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgel $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blel $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnel $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsl $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfl $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 14, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltl- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtl- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beql- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsol- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btl- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 6, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgel- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blel- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnel- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsl- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfl- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 15, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltl+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtl+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beql+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsol+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btl+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCL 7, crbitrc:$bi, condbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgel+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blel+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnel+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsl+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfl+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCLA:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 12, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltla $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtla $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqla $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsola $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btla $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 4, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgela $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blela $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnela $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsla $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfla $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 14, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltla- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtla- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqla- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsola- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btla- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 6, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgela- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blela- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnela- $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsla- $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfla- $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 15, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltla+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtla+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqla+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsola+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "btla+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1)) {
					 // (gBCLA 7, crbitrc:$bi, abscondbrtarget:$dst)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgela+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blela+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnela+ $\xFF\x03\x01";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnsla+ $\xFF\x03\x01";
							 break;
						 default:
							 AsmString = "bfla+ $\x02, $\xFF\x03\x01";
							 break;
					 }
					 break;
				 }
		case PPC_gBCLR:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 12, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlr";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlr";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlr";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolr";
							 break;
						 default:
							 AsmString = "btlr $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 4, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelr";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelr";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelr";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslr";
							 break;
						 default:
							 AsmString = "bflr $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 14, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlr-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlr-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlr-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolr-";
							 break;
						 default:
							 AsmString = "btlr- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 6, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelr-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelr-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelr-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslr-";
							 break;
						 default:
							 AsmString = "bflr- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 15, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlr+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlr+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlr+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolr+";
							 break;
						 default:
							 AsmString = "btlr+ $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLR 7, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelr+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelr+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelr+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslr+";
							 break;
						 default:
							 AsmString = "bflr+ $\x02";
							 break;
					 }
					 break;
				 }
				 return NULL;
		case PPC_gBCLRL:
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 12 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 12, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlrl";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlrl";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlrl";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolrl";
							 break;
						 default:
							 AsmString = "btlrl $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 4 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 4, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelrl";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelrl";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelrl";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslrl";
							 break;
						 default:
							 AsmString = "bflrl $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 14 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 14, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlrl-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlrl-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlrl-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolrl-";
							 break;
						 default:
							 AsmString = "btlrl- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 6 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 6, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelrl-";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelrl-";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelrl-";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslrl-";
							 break;
						 default:
							 AsmString = "bflrl- $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 15 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 15, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bltlrl+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "bgtlrl+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "beqlrl+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bsolrl+";
							 break;
						 default:
							 AsmString = "btlrl+ $\x02";
							 break;
					 }
					 break;
				 }
				 if (MCInst_getNumOperands(MI) == 3 &&
						 MCOperand_isImm(MCInst_getOperand(MI, 0)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 0)) == 7 &&
						 MCOperand_isReg(MCInst_getOperand(MI, 1)) &&
						 GETREGCLASS_CONTAIN(PPC_CRBITRCRegClassID, 1) &&
						 MCOperand_isImm(MCInst_getOperand(MI, 2)) &&
						 MCOperand_getImm(MCInst_getOperand(MI, 2)) == 0) {
					 // (gBCLRL 7, crbitrc:$bi, 0)
					 switch(PPC_map_register(MCOperand_getReg(MCInst_getOperand(MI, 1)))) {
						 case PPC_REG_R0:
							 AsmString = "bgelrl+";
							 break;
						 case PPC_REG_R1:
							 AsmString = "blelrl+";
							 break;
						 case PPC_REG_R2:
							 AsmString = "bnelrl+";
							 break;
						 case PPC_REG_R3:
							 AsmString = "bnslrl+";
							 break;
						 default:
							 AsmString = "bflrl+ $\x02";
							 break;
					 }
					 break;
				 }
				 return NULL;
	}

	tmp = cs_strdup(AsmString);
	AsmMnem = tmp;
	for(AsmOps = tmp; *AsmOps; AsmOps++) {
		if (*AsmOps == ' ' || *AsmOps == '\t') {
			*AsmOps = '\0';
			AsmOps++;
			break;
		}
	}
	SStream_concat0(OS, AsmMnem);
	if (*AsmOps) {
		SStream_concat0(OS, "\t");
		for (c = AsmOps; *c; c++) {
			if (*c == '$') {
				c += 1;
				if (*c == (char)0xff) {
					c += 1;
					OpIdx = *c - 1;
					c += 1;
					PrintMethodIdx = *c - 1;
					printCustomAliasOperand(MI, OpIdx, PrintMethodIdx, OS);
				} else
					printOperand(MI, *c - 1, OS);
			} else {
				SStream_concat(OS, "%c", *c);
			}
		}
	}
	return tmp;
}

#define PRINT_ALIAS_INSTR
#include "PPCGenAsmWriter.inc"

#endif
