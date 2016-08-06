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

static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->csh->detail != CS_OPT_ON)
		return;

	MI->csh->doing_mem = status;

	if (status) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = TRICORE_REG_INVALID;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = 0;
	} else {
		// done, create the next operand slot
		MI->flat_insn->detail->tricore.op_count++;
	}
}

void TriCore_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci)
{
	/*
	   if (((cs_struct *)ud)->detail != CS_OPT_ON)
	   return;
	 */
}

static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat0(OS, "%");
	SStream_concat0(OS, getRegisterName(RegNo));
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
		printRegName(O, reg);
		reg = TriCore_map_register(reg);
		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = reg;
			} else {
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = reg;
				MI->flat_insn->detail->tricore.op_count++;
			}
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (MI->csh->doing_mem) {
			if (imm) {	// only print Imm offset if it is not 0
				if (imm >= 0) {
					if (imm > HEX_THRESHOLD)
						SStream_concat(O, "0x%"PRIx64, imm);
					else
						SStream_concat(O, "%"PRIu64, imm);
				} else {
					if (imm < -HEX_THRESHOLD)
						SStream_concat(O, "-0x%"PRIx64, -imm);
					else
						SStream_concat(O, "-%"PRIu64, -imm);
				}
			}
			if (MI->csh->detail)
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = imm;
		} else {
			if (imm >= 0) {
				if (imm > HEX_THRESHOLD)
					SStream_concat(O, "0x%"PRIx64, imm);
				else
					SStream_concat(O, "%"PRIu64, imm);
			} else {
				if (imm < -HEX_THRESHOLD)
					SStream_concat(O, "-0x%"PRIx64, -imm);
				else
					SStream_concat(O, "-%"PRIu64, -imm);
			}

			if (MI->csh->detail) {
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
				MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = imm;
				MI->flat_insn->detail->tricore.op_count++;
			}
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
// TODO: verify this function
static void printAddrModeMemSrc(MCInst *MI, int OpNum, SStream *O) {

	set_mem_access(MI, true);
	MCOperand *Base = MCInst_getOperand(MI, OpNum);

	// Print register base field
	if (MCOperand_isReg(Base)) {
		SStream_concat(O, "[%");
		printRegName(O, MCOperand_getReg(Base));
		SStream_concat(O, "]");
	}

	SStream_concat(O, " ");
	printOperand(MI, OpNum+1, O); // Disp
	set_mem_access(MI, false);
}


#define PRINT_ALIAS_INSTR
#include "TriCoreGenAsmWriter.inc"

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	printInstruction(MI, O, Info);
	set_mem_access(MI, false);
}

#endif
