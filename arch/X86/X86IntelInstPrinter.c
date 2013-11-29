//===-- X86IntelInstPrinter.cpp - Intel assembly instruction printing -----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file includes code for rendering MCInst instances as Intel-style
// assembly.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"

#include "mapping.h"

static void printMemReference(MCInst *MI, unsigned Op, SStream *O);

static void printopaquemem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "opaque ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "byte ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "word ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "dword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "qword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "xmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "ymmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "zmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "dword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "qword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "xword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "xmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "ymmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "zmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);

	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].type = X86_OP_MEM;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.base = X86_REG_INVALID;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.index = X86_REG_INVALID;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.scale = 1;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.disp = 0;

	SStream_concat(O, "[");

	if (MCOperand_isImm(DispSpec)) {
		int64_t imm = MCOperand_getImm(DispSpec);
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.disp = imm;
		if (imm < 0)
			SStream_concat(O, "-0x%"PRIx64, -imm);
		else
			SStream_concat(O, "0x%"PRIx64, imm);
	}

	SStream_concat(O, "]");

	MI->pub_insn.x86.op_count++;
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "byte ptr ");
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "word ptr ");
	printMemOffset(MI, OpNo, O);

}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "dword ptr ");
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat(O, "qword ptr ");
	printMemOffset(MI, OpNo, O);
}

// get the first op from the asm buffer
// return False if there is no op. On True, put fist op in @firstop
// NOTE: make sure firstop is big enough to contain the resulted string
static bool get_first_op(char *buffer, char *firstop)
{
	char *tab = strchr(buffer, '\t');
	if (tab) {
		char *comma = strchr(tab + 1, ',');
		if (comma) {
			memcpy(firstop, tab + 1, comma - tab - 1);
			firstop[comma - tab - 1] = '\0';
		} else
			strcpy(firstop, tab + 1);

		return true;
	} else	// no op
		return false;
}

// hacky: get mnem string from buffer if this insn has only 1 operand
// return mnem if True, or False if above condition was not satisfied
// NOTE: make sure mnem is big enough to contain the resulted string
static bool get_mnem1(char *buffer, char *mnem)
{
	if (strchr(buffer, ','))
		return false;

	char *tab = strchr(buffer, '\t');
	if (!tab)
		return false;

	memcpy(mnem, buffer, tab - buffer);
	mnem[tab - buffer + 1] = '\0';

	return true;
}

static bool printAliasInstr(MCInst *MI, SStream *OS);
static void printInstruction(MCInst *MI, SStream *O);
void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)
{
	//const MCInstrDesc &Desc = MII.get(MI->getOpcode());
	// FIXME: target-specified flags need to be handled here
	//uint64_t TSFlags = Desc.TSFlags;

	//if (TSFlags & X86II::LOCK)
	//  O << "\tlock\n";

	if (printAliasInstr(MI, O)) {
		char *mnem = strdup(O->buffer);
		char *tab = strchr(mnem, '\t');
		if (tab)
			*tab = '\0';
		// reflect the new insn name (alias) in the opcode
		MCInst_setOpcode(MI, X86_get_insn_id2(X86_map_insn(mnem)));
		free(mnem);
	} else
		printInstruction(MI, O);

	// currently LLVM presents "shr reg, 1" as "shr reg"
	// until that is fixed, we need this hack
	char tmp[128];
	if (get_mnem1(O->buffer, tmp)) {
		char *mnems[] = {"shr", "shl", "sar", NULL};
		if (str_in_list(mnems, tmp)) {
			// this insn needs to have op "1"
			strcat(O->buffer, ", 1");
			MI->pub_insn.x86.operands[1].type = X86_OP_IMM;
			MI->pub_insn.x86.operands[1].imm = 1;
			MI->pub_insn.x86.op_count++;

			return;
		}
	}

	if (get_first_op(O->buffer, tmp)) {
		char *acc_regs[] = {"rax", "eax", "ax", "al", NULL};
		if (tmp[0] != 0 && str_in_list(acc_regs, tmp)) {
			// tmp is a register
			if (MI->pub_insn.x86.operands[0].type != X86_OP_INVALID &&
					MI->pub_insn.x86.operands[0].type != X86_OP_REG) {
				int i;
				for (i = MI->pub_insn.x86.op_count; i > 0; i--) {
					memcpy(&(MI->pub_insn.x86.operands[i]), &(MI->pub_insn.x86.operands[i - 1]),
							sizeof(MI->pub_insn.x86.operands[0]));
				}
				MI->pub_insn.x86.operands[0].type = X86_OP_REG;
				MI->pub_insn.x86.operands[0].reg = x86_map_regname(tmp);
				MI->pub_insn.x86.op_count++;
			}
		}
	}
}

static void printSSECC(MCInst *MI, unsigned Op, SStream *OS)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0xf;
	switch (Imm) {
		default: break;	// never reach
		case    0: SStream_concat(OS, "eq"); break;
		case    1: SStream_concat(OS, "lt"); break;
		case    2: SStream_concat(OS, "le"); break;
		case    3: SStream_concat(OS, "unord"); break;
		case    4: SStream_concat(OS, "neq"); break;
		case    5: SStream_concat(OS, "nlt"); break;
		case    6: SStream_concat(OS, "nle"); break;
		case    7: SStream_concat(OS, "ord"); break;
		case    8: SStream_concat(OS, "eq_uq"); break;
		case    9: SStream_concat(OS, "nge"); break;
		case  0xa: SStream_concat(OS, "ngt"); break;
		case  0xb: SStream_concat(OS, "false"); break;
		case  0xc: SStream_concat(OS, "neq_oq"); break;
		case  0xd: SStream_concat(OS, "ge"); break;
		case  0xe: SStream_concat(OS, "gt"); break;
		case  0xf: SStream_concat(OS, "true"); break;
	}
}

static void printAVXCC(MCInst *MI, unsigned Op, SStream *O)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0x1f;
	switch (Imm) {
		default: printf("Invalid avxcc argument!\n"); break;
		case    0: SStream_concat(O, "eq"); break;
		case    1: SStream_concat(O, "lt"); break;
		case    2: SStream_concat(O, "le"); break;
		case    3: SStream_concat(O, "unord"); break;
		case    4: SStream_concat(O, "neq"); break;
		case    5: SStream_concat(O, "nlt"); break;
		case    6: SStream_concat(O, "nle"); break;
		case    7: SStream_concat(O, "ord"); break;
		case    8: SStream_concat(O, "eq_uq"); break;
		case    9: SStream_concat(O, "nge"); break;
		case  0xa: SStream_concat(O, "ngt"); break;
		case  0xb: SStream_concat(O, "false"); break;
		case  0xc: SStream_concat(O, "neq_oq"); break;
		case  0xd: SStream_concat(O, "ge"); break;
		case  0xe: SStream_concat(O, "gt"); break;
		case  0xf: SStream_concat(O, "true"); break;
		case 0x10: SStream_concat(O, "eq_os"); break;
		case 0x11: SStream_concat(O, "lt_oq"); break;
		case 0x12: SStream_concat(O, "le_oq"); break;
		case 0x13: SStream_concat(O, "unord_s"); break;
		case 0x14: SStream_concat(O, "neq_us"); break;
		case 0x15: SStream_concat(O, "nlt_uq"); break;
		case 0x16: SStream_concat(O, "nle_uq"); break;
		case 0x17: SStream_concat(O, "ord_s"); break;
		case 0x18: SStream_concat(O, "eq_us"); break;
		case 0x19: SStream_concat(O, "nge_uq"); break;
		case 0x1a: SStream_concat(O, "ngt_uq"); break;
		case 0x1b: SStream_concat(O, "false_os"); break;
		case 0x1c: SStream_concat(O, "neq_os"); break;
		case 0x1d: SStream_concat(O, "ge_oq"); break;
		case 0x1e: SStream_concat(O, "gt_oq"); break;
		case 0x1f: SStream_concat(O, "true_us"); break;
	}
}

/// printPCRelImm - This is used to print an immediate value that ends up
/// being encoded as a pc-relative value.
static void printPCRelImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op) + MI->pub_insn.size + MI->pub_insn.address;
		if (imm < 0)
			SStream_concat(O, "-0x%"PRIx64, -imm);
		else
			SStream_concat(O, "0x%"PRIx64, imm);
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].type = X86_OP_IMM;
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].imm = imm;
		MI->pub_insn.x86.op_count++;
	}
}

static const char *getRegisterName(unsigned RegNo);
static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat(OS, getRegisterName(RegNo));
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].type = X86_OP_REG;
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].reg = MCOperand_getReg(Op);
		MI->pub_insn.x86.op_count++;
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (imm < 0)
			SStream_concat(O, "-0x%"PRIx64, -imm);
		else
			SStream_concat(O, "0x%"PRIx64, imm);
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].type = X86_OP_IMM;
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].imm = imm;
		MI->pub_insn.x86.op_count++;
	}
}

// local printOperand, without updating public operands
static void _printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (imm < 0)
			SStream_concat(O, "-0x%"PRIx64, -imm);
		else
			SStream_concat(O, "0x%"PRIx64, imm);
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)	// qqq
{
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op);
	unsigned ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op+1));
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op+2);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op+3);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+4);

	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].type = X86_OP_MEM;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.base = MCOperand_getReg(BaseReg);
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.index = MCOperand_getReg(IndexReg);
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.scale = ScaleVal;
	MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.disp = 0;

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		_printOperand(MI, Op+4, O);
		SStream_concat(O, ":");
	}

	SStream_concat(O, "[");

	bool NeedPlus = false;
	if (MCOperand_getReg(BaseReg)) {
		_printOperand(MI, Op, O);
		NeedPlus = true;
	}

	if (MCOperand_getReg(IndexReg)) {
		if (NeedPlus) SStream_concat(O, " + ");
		if (ScaleVal != 1)
			SStream_concat(O, "%u*", ScaleVal);
		_printOperand(MI, Op+2, O);
		NeedPlus = true;
	}

	if (!MCOperand_isImm(DispSpec)) {
		if (NeedPlus) SStream_concat(O, " + ");
		//assert(DispSpec.isExpr() && "non-immediate displacement for LEA?");
	} else {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		MI->pub_insn.x86.operands[MI->pub_insn.x86.op_count].mem.disp = DispVal;
		if (DispVal || (!MCOperand_getReg(IndexReg) && !MCOperand_getReg(BaseReg))) {
			if (NeedPlus) {
				if (DispVal > 0)
					SStream_concat(O, " + ");
				else {
					SStream_concat(O, " - ");
					DispVal = -DispVal;
				}
			}
			if (DispVal < 0)
				SStream_concat(O, "-0x%"PRIx64, -DispVal);
			else
				SStream_concat(O, "0x%"PRIx64, DispVal);
		}
	}

	SStream_concat(O, "]");
	MI->pub_insn.x86.op_count++;
}

#define GET_INSTRINFO_ENUM
#include "X86GenInstrInfo.inc"

#define PRINT_ALIAS_INSTR
#include "X86GenAsmWriter1.inc"

