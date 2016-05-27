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

// TODO: Implement all functions

static char *getRegisterName(unsigned RegNo);
static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI);
static void printMemOperand(MCInst *MI, int opNum, SStream *O, const char *Modifier);
static void printOperand(MCInst *MI, int opNum, SStream *O);

static void TriCore_add_reg(MCInst *MI, unsigned int reg)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = reg;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

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

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	printInstruction(MI, O, Info);
	set_mem_access(MI, false);
}

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (OpNum >= MI->size)
		return;
}

#define PRINT_ALIAS_INSTR
#include "TriCoreGenAsmWriter.inc"

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	printInstruction(MI, O, Info);
	set_mem_access(MI, false, 0);
}

#endif
