/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../MCInstPrinter.h"

#include "AlphaLinkage.h"
#include "AlphaMapping.h"

static const char *getRegisterName(unsigned RegNo);

static void printInstruction(MCInst *, uint64_t, SStream *);

static void printOperand(MCInst *MI, int OpNum, SStream *O);


#define GET_INSTRINFO_ENUM

#include "AlphaGenInstrInfo.inc"

#define GET_REGINFO_ENUM

#include "AlphaGenRegisterInfo.inc"

static inline void fill_alpha_register(MCInst *MI, uint32_t reg)
{
	if (!(MI->csh->detail == CS_OPT_ON && MI->flat_insn->detail))
		return;
	cs_alpha *alpha = &MI->flat_insn->detail->alpha;
	alpha->operands[alpha->op_count].type = ALPHA_OP_REG;
	alpha->operands[alpha->op_count].reg = reg;
	alpha->op_count++;
}

static inline void fill_alpha_imm(MCInst *MI, int32_t imm)
{
	if (!(MI->csh->detail == CS_OPT_ON && MI->flat_insn->detail))
		return;
	cs_alpha *alpha = &MI->flat_insn->detail->alpha;
	alpha->operands[alpha->op_count].type = ALPHA_OP_IMM;
	alpha->operands[alpha->op_count].imm = imm;
	alpha->op_count++;
}

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *Op;
	if (OpNum >= MI->size)
		return;

	Op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isReg(Op)) {
		unsigned reg = MCOperand_getReg(Op);
		SStream_concat(O, "%s", getRegisterName(reg));
		fill_alpha_register(MI, reg);
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

		fill_alpha_imm(MI, (int32_t)Imm);
	}
}

#define PRINT_ALIAS_INSTR

#include "AlphaGenAsmWriter.inc"

const char *Alpha_LLVM_getRegisterName(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return getRegisterName(id);
#else
	return NULL;
#endif
}

void Alpha_LLVM_printInst(MCInst *MI, SStream *O, void *Info)
{
	printAliasInstr(MI, MI->address, O);
	printInstruction(MI, MI->address, O);
}

#endif