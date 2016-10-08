//===- TriCoreInstPrinter.cpp - Convert TriCore MCInst to assembly syntax -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an TriCore MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <platform.h>

#include "TriCoreInstPrinter.h"
#include "../../MCInst.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "TriCoreMapping.h"

static char *getRegisterName(unsigned RegNo);
static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI);
static void printOperand(MCInst *MI, int OpNum, SStream *O);

void TriCore_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci)
{
	/*
	   if (((cs_struct *)ud)->detail != CS_OPT_ON)
	   return;
	 */
}

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "TriCoreGenRegisterInfo.inc"

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *Op;
	if (OpNum >= MI->size)
		return;

	Op = MCInst_getOperand(MI, OpNum);

	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);
		SStream_concat(O, "%%%s", getRegisterName(reg));
		reg = TriCore_map_register(reg);

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = reg;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t Imm = MCOperand_getImm(Op);

		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, Imm);
			else
				SStream_concat(O, "%"PRIu64, Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%"PRIx64, -Imm);
			else
				SStream_concat(O, "-%"PRIu64, -Imm);
		}

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = Imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	}
}

static void printSExtImm(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", (unsigned short int)imm);
			else
				SStream_concat(O, "%u", (unsigned short int)imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", (short int)-imm);
			else
				SStream_concat(O, "-%u", (short int)-imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = (unsigned short int)imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

static void printZExtImm(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		unsigned imm = (unsigned)MCOperand_getImm(MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

static void printPCRelImmOperand(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *Op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(Op)) {
		unsigned imm = (unsigned)MCOperand_getImm(Op);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
	}
	else
		printOperand(MI, OpNum, O);
}

// Print a 'memsrc' operand which is a (Register, Offset) pair.
static void printAddrModeMemSrc(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "]");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, Disp);
	else
		SStream_concat(O, "%"PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = (uint8_t)TriCore_map_register(Base);
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = (int64_t)Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

#define PRINT_ALIAS_INSTR
#include "TriCoreGenAsmWriter.inc"

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	printInstruction(MI, O, Info);
}

#endif
