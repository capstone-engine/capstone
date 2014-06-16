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

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_X86

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"

#include "X86Mapping.h"

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

static void printMemReference(MCInst *MI, unsigned Op, SStream *O);
static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);

static void printopaquemem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MI->Opcode == X86_BOUNDS16rm)
		SStream_concat0(O, "dword ptr ");
	else
		SStream_concat0(O, "word ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MI->Opcode == X86_BOUNDS32rm)
		SStream_concat0(O, "qword ptr ");
	else
		SStream_concat0(O, "dword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "xmmword ptr ");
	printMemReference(MI, OpNo, O);
}

#ifndef CAPSTONE_X86_REDUCE
static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "ymmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "zmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "xword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "xmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "ymmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "zmmword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printSSECC(MCInst *MI, unsigned Op, SStream *OS)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0xf;
	switch (Imm) {
		default: break;	// never reach
		case    0: SStream_concat0(OS, "eq"); break;
		case    1: SStream_concat0(OS, "lt"); break;
		case    2: SStream_concat0(OS, "le"); break;
		case    3: SStream_concat0(OS, "unord"); break;
		case    4: SStream_concat0(OS, "neq"); break;
		case    5: SStream_concat0(OS, "nlt"); break;
		case    6: SStream_concat0(OS, "nle"); break;
		case    7: SStream_concat0(OS, "ord"); break;
		case    8: SStream_concat0(OS, "eq_uq"); break;
		case    9: SStream_concat0(OS, "nge"); break;
		case  0xa: SStream_concat0(OS, "ngt"); break;
		case  0xb: SStream_concat0(OS, "false"); break;
		case  0xc: SStream_concat0(OS, "neq_oq"); break;
		case  0xd: SStream_concat0(OS, "ge"); break;
		case  0xe: SStream_concat0(OS, "gt"); break;
		case  0xf: SStream_concat0(OS, "true"); break;
	}
}

static void printAVXCC(MCInst *MI, unsigned Op, SStream *O)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0x1f;
	switch (Imm) {
		default: break;//printf("Invalid avxcc argument!\n"); break;
		case    0: SStream_concat0(O, "eq"); break;
		case    1: SStream_concat0(O, "lt"); break;
		case    2: SStream_concat0(O, "le"); break;
		case    3: SStream_concat0(O, "unord"); break;
		case    4: SStream_concat0(O, "neq"); break;
		case    5: SStream_concat0(O, "nlt"); break;
		case    6: SStream_concat0(O, "nle"); break;
		case    7: SStream_concat0(O, "ord"); break;
		case    8: SStream_concat0(O, "eq_uq"); break;
		case    9: SStream_concat0(O, "nge"); break;
		case  0xa: SStream_concat0(O, "ngt"); break;
		case  0xb: SStream_concat0(O, "false"); break;
		case  0xc: SStream_concat0(O, "neq_oq"); break;
		case  0xd: SStream_concat0(O, "ge"); break;
		case  0xe: SStream_concat0(O, "gt"); break;
		case  0xf: SStream_concat0(O, "true"); break;
		case 0x10: SStream_concat0(O, "eq_os"); break;
		case 0x11: SStream_concat0(O, "lt_oq"); break;
		case 0x12: SStream_concat0(O, "le_oq"); break;
		case 0x13: SStream_concat0(O, "unord_s"); break;
		case 0x14: SStream_concat0(O, "neq_us"); break;
		case 0x15: SStream_concat0(O, "nlt_uq"); break;
		case 0x16: SStream_concat0(O, "nle_uq"); break;
		case 0x17: SStream_concat0(O, "ord_s"); break;
		case 0x18: SStream_concat0(O, "eq_us"); break;
		case 0x19: SStream_concat0(O, "nge_uq"); break;
		case 0x1a: SStream_concat0(O, "ngt_uq"); break;
		case 0x1b: SStream_concat0(O, "false_os"); break;
		case 0x1c: SStream_concat0(O, "neq_os"); break;
		case 0x1d: SStream_concat0(O, "ge_oq"); break;
		case 0x1e: SStream_concat0(O, "gt_oq"); break;
		case 0x1f: SStream_concat0(O, "true_us"); break;
	}
}

static void printRoundingControl(MCInst *MI, unsigned Op, SStream *O)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0x3;
	switch (Imm) {
		case 0: SStream_concat0(O, "{rn-sae}"); break;
		case 1: SStream_concat0(O, "{rd-sae}"); break;
		case 2: SStream_concat0(O, "{ru-sae}"); break;
		case 3: SStream_concat0(O, "{rz-sae}"); break;
		default: break;	// never reach
	}
}

#endif

static void printSrcIdx(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *SegReg;

	SegReg = MCInst_getOperand(MI, Op+1);

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		printOperand(MI, Op+1, O);
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "[");
	printOperand(MI, Op, O);
	SStream_concat0(O, "]");
}

static void printDstIdx(MCInst *MI, unsigned Op, SStream *O)
{
	// DI accesses are always ES-based on non-64bit mode
	if (MI->csh->mode != CS_MODE_64)
		SStream_concat(O, "es:[");
	else
		SStream_concat(O, "[");
	printOperand(MI, Op, O);
	SStream_concat0(O, "]");
}

void printSrcIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	printSrcIdx(MI, OpNo, O);
}

void printSrcIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");
	printSrcIdx(MI, OpNo, O);
}

void printSrcIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	printSrcIdx(MI, OpNo, O);
}

void printSrcIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	printSrcIdx(MI, OpNo, O);
}

void printDstIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	printDstIdx(MI, OpNo, O);
}

void printDstIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");
	printDstIdx(MI, OpNo, O);
}

void printDstIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	printDstIdx(MI, OpNo, O);
}

void printDstIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	printDstIdx(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+1);

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		printOperand(MI, Op+1, O);
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "[");

	if (MCOperand_isImm(DispSpec)) {
		int64_t imm = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;
		if (imm < 0) {
			SStream_concat(O, "0x%"PRIx64, arch_masks[MI->csh->mode] & imm);
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, imm);
			else
				SStream_concat(O, "%"PRIu64, imm);
		}
	}

	SStream_concat0(O, "]");

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");

	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");

	printMemOffset(MI, OpNo, O);

}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");

	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	printMemOffset(MI, OpNo, O);
}

static char *printAliasInstr(MCInst *MI, SStream *OS, void *info);
static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI);
void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)
{
	char *mnem;
	x86_reg reg;

	// Try to print any aliases first.
	mnem = printAliasInstr(MI, O, NULL);
	if (mnem)
		cs_mem_free(mnem);
	else
		printInstruction(MI, O, NULL);

	if (MI->csh->detail) {
		// first op can be embedded in the asm by llvm.
		// so we have to handle that case to not miss the first op.
		reg = X86_insn_reg(MCInst_getOpcode(MI));
		if (reg) {
			// shift all the ops right to leave 1st slot for this new register op
			memmove(&(MI->flat_insn->detail->x86.operands[1]), &(MI->flat_insn->detail->x86.operands[0]),
					sizeof(MI->flat_insn->detail->x86.operands[0]) * (ARR_SIZE(MI->flat_insn->detail->x86.operands) - 1));
			MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
			MI->flat_insn->detail->x86.operands[0].reg = reg;
			MI->flat_insn->detail->x86.op_count++;
		}

	}
}

/// printPCRelImm - This is used to print an immediate value that ends up
/// being encoded as a pc-relative value.
static void printPCRelImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op) + MI->flat_insn->size + MI->address;
		if (imm < 0) {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%"PRIx64, -imm);
			else
				SStream_concat(O, "-%"PRIu64, -imm);
		} else {
			// handle 16bit segment bound
			if (MI->csh->mode == CS_MODE_16 && imm > 0x100000)
				imm -= 0x10000;

			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, imm);
			else
				SStream_concat(O, "%"PRIu64, imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;
			MI->flat_insn->detail->x86.op_count++;
		}
	}
}

static char *getRegisterName(unsigned RegNo);
static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat0(OS, getRegisterName(RegNo));
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_REG;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].reg = MCOperand_getReg(Op);
			MI->flat_insn->detail->x86.op_count++;
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
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
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;
			MI->flat_insn->detail->x86.op_count++;
		}
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
		if (imm < 0) {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%"PRIx64, -imm);
			else
				SStream_concat(O, "-%"PRIu64, -imm);

		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, imm);
			else
				SStream_concat(O, "%"PRIu64, imm);
		}
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)
{
	bool NeedPlus = false;
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op);
	uint64_t ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op+1));
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op+2);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op+3);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+4);

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = MCOperand_getReg(BaseReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = MCOperand_getReg(IndexReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = (int)ScaleVal;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		_printOperand(MI, Op+4, O);
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "[");

	if (MCOperand_getReg(BaseReg)) {
		_printOperand(MI, Op, O);
		NeedPlus = true;
	}

	if (MCOperand_getReg(IndexReg)) {
		if (NeedPlus) SStream_concat0(O, " + ");
		_printOperand(MI, Op+2, O);
		if (ScaleVal != 1)
			SStream_concat(O, "*%u", ScaleVal);
		NeedPlus = true;
	}

	if (!MCOperand_isImm(DispSpec)) {
		if (NeedPlus)
			SStream_concat0(O, " + ");
	} else {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = DispVal;
		if (DispVal || (!MCOperand_getReg(IndexReg) && !MCOperand_getReg(BaseReg))) {
			if (NeedPlus) {
				SStream_concat0(O, " + ");
			}

			if (DispVal < 0) {
				SStream_concat(O, "0x%"PRIx64, arch_masks[MI->csh->mode] & DispVal);
			} else {
				if (DispVal > HEX_THRESHOLD)
					SStream_concat(O, "0x%"PRIx64, DispVal);
				else
					SStream_concat(O, "%"PRIu64, DispVal);
			}
		}
	}

	SStream_concat0(O, "]");

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

#define PRINT_ALIAS_INSTR
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenAsmWriter1_reduce.inc"
#else
#include "X86GenAsmWriter1.inc"
#endif

#endif
