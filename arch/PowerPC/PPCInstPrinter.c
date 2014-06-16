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
	if (strrchr(insn_asm, '+') != NULL) {
		insn->detail->ppc.bh = PPC_BH_PLUS;
	} else if (strrchr(insn_asm, '-') != NULL) {
		insn->detail->ppc.bh = PPC_BH_MINUS;
	}
}

#define GET_INSTRINFO_ENUM
#include "PPCGenInstrInfo.inc"

void PPC_printInst(MCInst *MI, SStream *O, void *Info)
{
	// Check for slwi/srwi mnemonics.
	if (MCInst_getOpcode(MI) == PPC_RLWINM) {
		unsigned char SH = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 2));
		unsigned char MB = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 3));
		unsigned char ME = (unsigned char)MCOperand_getImm(MCInst_getOperand(MI, 4));
		bool useSubstituteMnemonic = false;

		if (SH <= 31 && MB == 0 && ME == (31-SH)) {
			SStream_concat0(O, "slwi\t");
			useSubstituteMnemonic = true;
		}

		if (SH <= 31 && MB == (32-SH) && ME == 31) {
			SStream_concat0(O, "srwi\t");
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

	printInstruction(MI, O, NULL);
}


static void printPredicateOperand(MCInst *MI, unsigned OpNo,
		SStream *O, const char *Modifier)
{
	unsigned Code = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, OpNo));

	MI->flat_insn->detail->ppc.bc = (ppc_bc)Code;

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
			default:	// unreachable
				return;
		}
		// llvm_unreachable("Invalid predicate code");
	}

	//assert(StringRef(Modifier) == "reg" &&
	//		"Need to specify 'cc', 'pm' or 'reg' as predicate op modifier!");
	printOperand(MI, OpNo + 1, O);
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
	SStream_concat0(O, ".+");
	printAbsBranchOperand(MI, OpNo, O);
}

static void printAbsBranchOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	int tmp;
	if (!MCOperand_isImm(MCInst_getOperand(MI, OpNo))) {
		printOperand(MI, OpNo, O);
		return;
	}

	tmp = (int)MCOperand_getImm(MCInst_getOperand(MI, OpNo)) * 4;
	if (tmp >= 0) {
		if (tmp > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", tmp);
		else
			SStream_concat(O, "%u", tmp);
	} else {
		if (tmp < -HEX_THRESHOLD)
			SStream_concat(O, "-0x%x", -tmp);
		else
			SStream_concat(O, "-%u", -tmp);
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
	printBranchOperand(MI, OpNo, O);
	SStream_concat0(O, "(");
	printOperand(MI, OpNo + 1, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
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

//#define PRINT_ALIAS_INSTR
#include "PPCGenAsmWriter.inc"

#endif
