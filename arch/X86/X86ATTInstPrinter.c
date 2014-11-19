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
#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_ATT_DISABLE)

#include <ctype.h>
#include "../../inttypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "X86Mapping.h"
#include "X86BaseInfo.h"


#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

static void printMemReference(MCInst *MI, unsigned Op, SStream *O);
static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);


static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->csh->detail != CS_OPT_ON)
		return;

	MI->csh->doing_mem = status;
	if (!status)
		// done, create the next operand slot
		MI->flat_insn->detail->x86.op_count++;
}

static void printopaquemem(MCInst *MI, unsigned OpNo, SStream *O)
{
	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MI->Opcode == X86_BOUNDS16rm)
		MI->x86opsize = 4;
	else
		MI->x86opsize = 2;

	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	if (MI->Opcode == X86_BOUNDS32rm)
		MI->x86opsize = 8;
	else
		MI->x86opsize = 4;

	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

#ifndef CAPSTONE_X86_REDUCE
static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 64;
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 10;
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 64;
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
		case 0: SStream_concat0(O, "{rn-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RN); break;
		case 1: SStream_concat0(O, "{rd-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RD); break;
		case 2: SStream_concat0(O, "{ru-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RU); break;
		case 3: SStream_concat0(O, "{rz-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RZ); break;
		default: break;	// nev0er reach
	}
}

#endif

static void printRegName(SStream *OS, unsigned RegNo);

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
				SStream_concat(O, "$-0x%"PRIx64, -imm);
			else
				SStream_concat(O, "$-%"PRIu64, -imm);
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "$0x%"PRIx64, imm);
			else
				SStream_concat(O, "$%"PRIu64, imm);
		}
	}
}

static void printSrcIdx(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *SegReg;
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	SegReg = MCInst_getOperand(MI, Op+1);
	reg = MCOperand_getReg(SegReg);

	// If this has a segment register, print it.
	if (reg) {
		_printOperand(MI, Op+1, O);
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}

		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "(");
	set_mem_access(MI, true);

	printOperand(MI, Op, O);

	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printDstIdx(MCInst *MI, unsigned Op, SStream *O)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// DI accesses are always ES-based on non-64bit mode
	if (MI->csh->mode != CS_MODE_64) {
		SStream_concat0(O, "%es:(");
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_ES;
		}
	} else
		SStream_concat0(O, "(");

	set_mem_access(MI, true);

	printOperand(MI, Op, O);

	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printSrcIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printSrcIdx(MI, OpNo, O);
}

static void printDstIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printDstIdx(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+1);
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + 1, O);
		SStream_concat0(O, ":");
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}
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

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemOffset(MI, OpNo, O);
}

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
			SStream_concat(O, "0x%"PRIx64, imm);
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
			MI->has_imm = true;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;
			MI->flat_insn->detail->x86.op_count++;
		}
	}
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);
		printRegName(O, reg);
		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = reg;
			} else {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].reg = reg;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->csh->regsize_map[reg];
				MI->flat_insn->detail->x86.op_count++;
			}
		}
	} else if (MCOperand_isImm(Op)) {
		// Print X86 immediates as signed values.
		int64_t imm = MCOperand_getImm(Op);

		switch(MI->flat_insn->id) {
			default:
				if (imm >= 0) {
					if (imm > HEX_THRESHOLD)
						SStream_concat(O, "$0x%"PRIx64, imm);
					else
						SStream_concat(O, "$%"PRIu64, imm);
				} else {
					if (imm < -HEX_THRESHOLD)
						SStream_concat(O, "$-0x%"PRIx64, -imm);
					else
						SStream_concat(O, "$-%"PRIu64, -imm);
				}
				break;
			case X86_INS_RET:
				// RET imm16
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					SStream_concat(O, "$%u", imm);
				else {
					imm = 0xffff & imm;
					SStream_concat(O, "$0x%x", imm);
				}
				break;
		}

		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;
			} else {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
				MI->has_imm = true;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;
				MI->flat_insn->detail->x86.op_count++;
			}
		}
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op + X86_AddrBaseReg);
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op + X86_AddrIndexReg);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op + X86_AddrDisp);
	MCOperand *SegReg = MCInst_getOperand(MI, Op + X86_AddrSegmentReg);
	uint64_t ScaleVal;
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = MCOperand_getReg(BaseReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = MCOperand_getReg(IndexReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + X86_AddrSegmentReg, O);
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}

		SStream_concat0(O, ":");
	}

	if (MCOperand_isImm(DispSpec)) {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = DispVal;
		if (DispVal) {
			if (MCOperand_getReg(IndexReg) || MCOperand_getReg(BaseReg)) {
				if (DispVal < 0) {
					if (DispVal <  -HEX_THRESHOLD)
						SStream_concat(O, "-0x%"PRIx64, -DispVal);
					else
						SStream_concat(O, "-%"PRIu64, -DispVal);
				} else {
					if (DispVal > HEX_THRESHOLD)
						SStream_concat(O, "0x%"PRIx64, DispVal);
					else
						SStream_concat(O, "%"PRIu64, DispVal);
				}
			} else {
				// only immediate as address of memory
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
	}

	if (MCOperand_getReg(IndexReg) || MCOperand_getReg(BaseReg)) {
		SStream_concat0(O, "(");

		if (MCOperand_getReg(BaseReg))
			_printOperand(MI, Op + X86_AddrBaseReg, O);

		if (MCOperand_getReg(IndexReg)) {
			SStream_concat0(O, ", ");
			_printOperand(MI, Op + X86_AddrIndexReg, O);
			ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op + X86_AddrScaleAmt));
			if (MI->csh->detail)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = (int)ScaleVal;
			if (ScaleVal != 1) {
				SStream_concat(O, ", %u", ScaleVal);
			}
		}
		SStream_concat0(O, ")");
	}

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
	SStream_concat(OS, "%%%s", getRegisterName(RegNo));
}

void X86_ATT_printInst(MCInst *MI, SStream *OS, void *info)
{
	char *mnem;
	x86_reg reg;
	int i;

	// Output CALLpcrel32 as "callq" in 64-bit mode.
	// In Intel annotation it's always emitted as "call".
	//
	// TODO: Probably this hack should be redesigned via InstAlias in
	// InstrInfo.td as soon as Requires clause is supported properly
	// for InstAlias.
	if (MI->csh->mode == CS_MODE_64 && MCInst_getOpcode(MI) == X86_CALLpcrel32) {
		SStream_concat0(OS, "callq\t");
		MCInst_setOpcodePub(MI, X86_INS_CALL);
		printPCRelImm(MI, 0, OS);
		return;
	}

	// Try to print any aliases first.
	mnem = printAliasInstr(MI, OS, info);
	if (mnem)
		cs_mem_free(mnem);
	else
		printInstruction(MI, OS, info);

	if (MI->has_imm) {
		// if op_count > 1, then this operand's size is taken from the destination op
		if (MI->flat_insn->detail->x86.op_count > 1) {
			for (i = 0; i < MI->flat_insn->detail->x86.op_count; i++) {
				if (MI->flat_insn->detail->x86.operands[i].type == X86_OP_IMM)
					MI->flat_insn->detail->x86.operands[i].size = MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count - 1].size;
			}
		} else
			MI->flat_insn->detail->x86.operands[0].size = MI->imm_size;
	}

	if (MI->csh->detail) {
		// special instruction needs to supply register op
		// first op can be embedded in the asm by llvm.
		// so we have to add the missing register as the first operand
		reg = X86_insn_reg_att(MCInst_getOpcode(MI));
		if (reg) {
			// shift all the ops right to leave 1st slot for this new register op
			memmove(&(MI->flat_insn->detail->x86.operands[1]), &(MI->flat_insn->detail->x86.operands[0]),
					sizeof(MI->flat_insn->detail->x86.operands[0]) * (ARR_SIZE(MI->flat_insn->detail->x86.operands) - 1));
			MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
			MI->flat_insn->detail->x86.operands[0].reg = reg;
			MI->flat_insn->detail->x86.operands[0].size = MI->csh->regsize_map[reg];
			MI->flat_insn->detail->x86.op_count++;
		}
	}
}

#endif
