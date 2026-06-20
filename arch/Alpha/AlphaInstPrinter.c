/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../Mapping.h"
#include "../../MCInstPrinter.h"

#include "AlphaLinkage.h"
#include "AlphaMapping.h"

static const char *getRegisterName(unsigned RegNo);

static void printInstruction(MCInst *, uint64_t, SStream *);
static void printOperand(MCInst *MI, int OpNum, SStream *O);
static void printOperandAddr(MCInst *MI, uint64_t Address, unsigned OpNum,
			     SStream *O);

#define GET_INSTRINFO_ENUM

#include "AlphaGenInstrInfo.inc"

#define GET_REGINFO_ENUM

#include "AlphaGenRegisterInfo.inc"

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (OpNum >= MI->size)
		return;

	Alpha_add_cs_detail(MI, OpNum);

	MCOperand *Op;
	Op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isReg(Op)) {
		unsigned reg = MCOperand_getReg(Op);
		SStream_concat(O, "%s", getRegisterName(reg));
	} else if (MCOperand_isImm(Op)) {
		int64_t Imm = MCOperand_getImm(Op);
		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%" PRIx64, Imm);
			else
				SStream_concat(O, "%" PRIu64, Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%" PRIx64, -Imm);
			else
				SStream_concat(O, "-%" PRIu64, -Imm);
		}
	}
}

static void printOperandAddr(MCInst *MI, uint64_t Address, unsigned OpNum,
			     SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, (OpNum));

	uint64_t Imm = MCOperand_getImm(Op);
	uint64_t Target = Address + 4 + (int16_t)(Imm << 2);

	Alpha_set_detail_op_imm(MI, OpNum, ALPHA_OP_IMM, Target);
	printUInt64(O, Target);
}

#define PRINT_ALIAS_INSTR

#include "AlphaGenAsmWriter.inc"

const char *ALPHA_LLVM_getRegisterName(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return getRegisterName(id);
#else
	return NULL;
#endif
}

void ALPHA_LLVM_printInstruction(MCInst *MI, SStream *O, void *Info)
{
	unsigned Opcode = MCInst_getOpcode(MI);
	/*
	 * The generated AsmWriter hardcodes "$31" for BR and restricts BSR to
	 * Ra=26. Format 27 now decodes Ra as operand[0] and disp21 as
	 * operand[1], so we must print them explicitly here.
	 */
	if (Opcode == ALPHA_COND_BRANCH_I) {
		SStream_concat0(O, "call_pal ");
		printOperand(MI, 0, O);
		return;
	}
	/*
	 * JMP/JSR/JSRs now decode with format 18 (Ra + Rb + hint14).
	 * The generated AsmWriter hardcodes operands for specific canonical
	 * forms, so print all three operands explicitly here.
	 */
	if (Opcode == ALPHA_JMP || Opcode == ALPHA_JSR ||
	    Opcode == ALPHA_JSRs || Opcode == ALPHA_RETDAG) {
		const char *name = (Opcode == ALPHA_JMP)    ? "jmp " :
				   (Opcode == ALPHA_RETDAG) ? "ret " :
							      "jsr ";
		SStream_concat0(O, name);
		printOperand(MI, 0, O);
		SStream_concat1(O, ',');
		SStream_concat1(O, '(');
		printOperand(MI, 1, O);
		SStream_concat1(O, ')');
		SStream_concat1(O, ',');
		printOperand(MI, 2, O);
		return;
	}
	if (Opcode == ALPHA_BR || Opcode == ALPHA_BSR) {
		SStream_concat0(O, Opcode == ALPHA_BR ? "br " : "bsr ");
		printOperand(MI, 0, O);
		SStream_concat1(O, ',');
		printOperandAddr(MI, MI->address, 1, O);
		return;
	}
	printAliasInstr(MI, MI->address, O);
	printInstruction(MI, MI->address, O);
}

#endif