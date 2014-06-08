//===-- X86ATTInstPrinter.cpp - AT&T assembly instruction printing --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file includes code for rendering MCInst instances as AT&T-style
// assembly.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

// this code is only relevant when DIET mode is disable
#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET)

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

#define markup(x) ""


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
	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

#ifndef CAPSTONE_X86_REDUCE
static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
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
		default: break;	// nev0er reach
	}
}

#endif

static void printSrcIdx(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *SegReg;

	SegReg = MCInst_getOperand(MI, Op+1);

	SStream_concat0(O, markup("<mem:"));

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		printOperand(MI, Op+1, O);
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "(");

	printOperand(MI, Op, O);

	SStream_concat(O, ")%s", markup(">"));
}

static void printDstIdx(MCInst *MI, unsigned Op, SStream *O)
{
	SStream_concat(O, "%s%s", markup("<mem:"), "%es:(");
	printOperand(MI, Op, O);

	SStream_concat(O, ")%s", markup(">"));
}

static void printSrcIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	printSrcIdx(MI, OpNo, O);
}

static void printDstIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	printDstIdx(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+1);

	SStream_concat0(O, markup("<mem:"));

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		printOperand(MI, Op+1, O);
		SStream_concat0(O, ":");
	}

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

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

	SStream_concat0(O, markup(">"));

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemOffset(MI, OpNo, O);
}

static void printRegName(SStream *OS, unsigned RegNo);

/// printPCRelImm - This is used to print an immediate value that ends up
/// being encoded as a pc-relative value (e.g. for jumps and calls).  These
/// print slightly differently than normal immediates.  For example, a $ is not
/// emitted.
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
		// Print X86 immediates as signed values.
		int64_t imm = MCOperand_getImm(Op);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "%s$0x%"PRIx64"%s", markup("<imm:"), imm, markup(">"));
			else
				SStream_concat(O, "%s$%"PRIu64"%s", markup("<imm:"), imm, markup(">"));
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "%s$-0x%"PRIx64"%s", markup("<imm:"), -imm, markup(">"));
			else
				SStream_concat(O, "%s$-%"PRIu64"%s", markup("<imm:"), -imm, markup(">"));
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
		// Print X86 immediates as signed values.
		int64_t imm = MCOperand_getImm(Op);
		if (imm < 0) {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "%s$-0x%"PRIx64"%s", markup("<imm:"), -imm, markup(">"));
			else
				SStream_concat(O, "%s$-%"PRIu64"%s", markup("<imm:"), -imm, markup(">"));
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "%s$0x%"PRIx64"%s", markup("<imm:"), imm, markup(">"));
			else
				SStream_concat(O, "%s$%"PRIu64"%s", markup("<imm:"), imm, markup(">"));
		}
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op);
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op+2);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op+3);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+4);
	uint64_t ScaleVal;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = MCOperand_getReg(BaseReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = MCOperand_getReg(IndexReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	SStream_concat0(O, markup("<mem:"));

	// If this has a segment register, print it.
	if (MCOperand_getReg(SegReg)) {
		_printOperand(MI, Op+4, O);
		SStream_concat0(O, ":");
	}

	if (MCOperand_isImm(DispSpec)) {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = DispVal;
		if (DispVal || (!MCOperand_getReg(IndexReg) && !MCOperand_getReg(BaseReg))) {
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

	if (MCOperand_getReg(IndexReg) || MCOperand_getReg(BaseReg)) {
		SStream_concat0(O, "(");

		if (MCOperand_getReg(BaseReg))
			_printOperand(MI, Op, O);

		if (MCOperand_getReg(IndexReg)) {
			SStream_concat0(O, ", ");
			_printOperand(MI, Op+2, O);
			ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op+1));
			if (MI->csh->detail)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = (int)ScaleVal;
			if (ScaleVal != 1) {
				SStream_concat(O, ", %s%u%s", markup("<imm:"), ScaleVal, markup(">"));
			}
		}
		SStream_concat0(O, ")");
	}

	SStream_concat0(O, markup(">"));

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

#include "X86InstPrinter.h"

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenAsmWriter_reduce.inc"
#else
#include "X86GenAsmWriter.inc"
#endif

static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat(OS, "%s%%%s%s", markup("<reg:"), getRegisterName(RegNo), markup(">"));
}

void X86_ATT_printInst(MCInst *MI, SStream *OS, void *info)
{
	char *mnem;
	unsigned int i;
	x86_reg reg;

	// Try to print any aliases first.
	mnem = printAliasInstr(MI, OS, NULL);
	if (mnem)
		cs_mem_free(mnem);
	else
		printInstruction(MI, OS, NULL);

	if (MI->csh->detail) {
		// special instruction needs to supply register op
		reg = X86_insn_reg(MCInst_getOpcode(MI));
		if (reg) {
			// add register operand
			for (i = 0;; i++) {
				// find the first empty slot to put it there
				if (MI->flat_insn->detail->x86.operands[i].type == 0) {
					MI->flat_insn->detail->x86.operands[i].type = X86_OP_REG;
					MI->flat_insn->detail->x86.operands[i].reg = reg;
					MI->flat_insn->detail->x86.op_count++;
					break;
				}
			}

		}
	}
}

#endif
