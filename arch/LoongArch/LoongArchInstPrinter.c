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

//===- LoongArchInstPrinter.cpp - Convert LoongArch MCInst to asm syntax --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an LoongArch MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "LoongArchMapping.h"
#include "LoongArchInstPrinter.h"

#define GET_SUBTARGETINFO_ENUM
#include "LoongArchGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "LoongArchGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "LoongArchGenRegisterInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "loongarch-asm-printer"

// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#include "LoongArchGenAsmWriter.inc"

static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O)
{
	bool useAliasDetails = map_use_alias_details(MI);
	map_set_fill_detail_ops(MI, useAliasDetails);

	bool isAlias = printAliasInstr(MI, Address, O);

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

void LoongArch_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			      SStream *O)
{
	printInst(MI, Address, Annot, O);
}

const char *LoongArch_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx)
{
	return getRegisterName(RegNo, AltIdx);
}

static void printRegName(MCInst *MI, SStream *O, MCRegister Reg)
{
	int syntax_opt = MI->csh->syntax;
	if (!(syntax_opt & CS_OPT_SYNTAX_NO_DOLLAR)) {
		SStream_concat1(O, '$');
	}
	SStream_concat0(O, getRegisterName(Reg, LoongArch_RegAliasName));
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, LoongArch_OP_GROUP_Operand, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	if (MCOperand_isReg(MO)) {
		printRegName(MI, O, MCOperand_getReg(MO));
		return;
	}

	if (MCOperand_isImm(MO)) {
		// rewrite offset immediate operand to absolute address in direct branch instructions
		// convert e.g.
		// 0x1000: beqz	$t0, 0xc
		// to:
		// 0x1000: beqz	$t0, 0x100c
		switch (MI->flat_insn->id) {
		case LOONGARCH_INS_B:
		case LOONGARCH_INS_BCEQZ:
		case LOONGARCH_INS_BCNEZ:
		case LOONGARCH_INS_BEQ:
		case LOONGARCH_INS_BEQZ:
		case LOONGARCH_INS_BGE:
		case LOONGARCH_INS_BGEU:
		case LOONGARCH_INS_BL:
		case LOONGARCH_INS_BLT:
		case LOONGARCH_INS_BLTU:
		case LOONGARCH_INS_BNE:
		case LOONGARCH_INS_BNEZ:
			printInt64(O, MCOperand_getImm(MO) + MI->address);
			return;

		default:
			break;
		}

		printInt64(O, MCOperand_getImm(MO));
		return;
	}

	CS_ASSERT_RET(0 && "Expressions are not supported.");
}

static void printAtomicMemOp(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, LoongArch_OP_GROUP_AtomicMemOp, OpNo);
	MCOperand *MO = MCInst_getOperand(MI, (OpNo));

	printRegName(MI, O, MCOperand_getReg(MO));
}
