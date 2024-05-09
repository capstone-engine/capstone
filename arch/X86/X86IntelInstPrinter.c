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
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_X86

#ifdef _MSC_VER
#pragma warning(disable:4996)			// disable MSVC's warning on strncpy()
#pragma warning(disable:28719)		// disable MSVC's warning on strncpy()
#endif

#if !defined(CAPSTONE_HAS_OSXKERNEL)
#include <ctype.h>
#endif
#include <capstone/platform.h>

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <string.h>

#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"

#include "X86InstPrinter.h"
#include "X86Mapping.h"
#include "X86InstPrinterCommon.h"

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

#include "X86BaseInfo.h"

static void printMemReference(MCInst *MI, unsigned Op, SStream *O);
static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);


static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->csh->detail_opt != CS_OPT_ON)
		return;

	MI->csh->doing_mem = status;
	if (!status)
		// done, create the next operand slot
		MI->flat_insn->detail->x86.op_count++;

}

static void printopaquemem(MCInst *MI, unsigned OpNo, SStream *O)
{
	// FIXME: do this with autogen
	// printf(">>> ID = %u\n", MI->flat_insn->id);
	switch(MI->flat_insn->id) {
		default:
			SStream_concat0(O, "ptr ");
			break;
		case X86_INS_SGDT:
		case X86_INS_SIDT:
		case X86_INS_LGDT:
		case X86_INS_LIDT:
		case X86_INS_FXRSTOR:
		case X86_INS_FXSAVE:
		case X86_INS_LJMP:
		case X86_INS_LCALL:
			// do not print "ptr"
			break;
	}

	switch(MI->csh->mode) {
		case CS_MODE_16:
			switch(MI->flat_insn->id) {
				default:
					MI->x86opsize = 2;
					break;
				case X86_INS_LJMP:
				case X86_INS_LCALL:
					MI->x86opsize = 4;
					break;
				case X86_INS_SGDT:
				case X86_INS_SIDT:
				case X86_INS_LGDT:
				case X86_INS_LIDT:
					MI->x86opsize = 6;
					break;
			}
			break;
		case CS_MODE_32:
			switch(MI->flat_insn->id) {
				default:
					MI->x86opsize = 4;
					break;
				case X86_INS_LJMP:
				case X86_INS_JMP:
				case X86_INS_LCALL:
				case X86_INS_SGDT:
				case X86_INS_SIDT:
				case X86_INS_LGDT:
				case X86_INS_LIDT:
					MI->x86opsize = 6;
					break;
			}
			break;
		case CS_MODE_64:
			switch(MI->flat_insn->id) {
				default:
					MI->x86opsize = 8;
					break;
				case X86_INS_LJMP:
				case X86_INS_LCALL:
				case X86_INS_SGDT:
				case X86_INS_SIDT:
				case X86_INS_LGDT:
				case X86_INS_LIDT:
					MI->x86opsize = 10;
					break;
			}
			break;
		default:	// never reach
			break;
	}

	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	MI->x86opsize = 1;
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	SStream_concat0(O, "word ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	SStream_concat0(O, "dword ptr ");
	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	MI->x86opsize = 8;
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "xmmword ptr ");
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "zmmword ptr ");
	MI->x86opsize = 64;
	printMemReference(MI, OpNo, O);
}

#ifndef CAPSTONE_X86_REDUCE
static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "ymmword ptr ");
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	switch(MCInst_getOpcode(MI)) {
		default:
			SStream_concat0(O, "dword ptr ");
			MI->x86opsize = 4;
			break;
		case X86_FSTENVm:
		case X86_FLDENVm:
			// TODO: fix this in tablegen instead
			switch(MI->csh->mode) {
				default:    // never reach
					break;
				case CS_MODE_16:
					MI->x86opsize = 14;
					break;
				case CS_MODE_32:
				case CS_MODE_64:
					MI->x86opsize = 28;
					break;
			}
			break;
	}

	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	// TODO: fix COMISD in Tablegen instead (#1456)
	if (MI->op1_size == 16) {
		// printf("printf64mem id = %u\n", MCInst_getOpcode(MI));
		switch(MCInst_getOpcode(MI)) {
			default:
				SStream_concat0(O, "qword ptr ");
				MI->x86opsize = 8;
				break;
			case X86_MOVPQI2QImr:
			case X86_COMISDrm:
				SStream_concat0(O, "xmmword ptr ");
				MI->x86opsize = 16;
				break;
		}
	} else {
		SStream_concat0(O, "qword ptr ");
		MI->x86opsize = 8;
	}

	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	switch(MCInst_getOpcode(MI)) {
		default:
			SStream_concat0(O, "xword ptr ");
			break;
		case X86_FBLDm:
		case X86_FBSTPm:
			break;
	}

	MI->x86opsize = 10;
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "xmmword ptr ");
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "ymmword ptr ");
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "zmmword ptr ");
	MI->x86opsize = 64;
	printMemReference(MI, OpNo, O);
}
#endif

static const char *getRegisterName(unsigned RegNo);
static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat0(OS, getRegisterName(RegNo));
}

// for MASM syntax, 0x123 = 123h, 0xA123 = 0A123h
// this function tell us if we need to have prefix 0 in front of a number
static bool need_zero_prefix(uint64_t imm)
{
	// find the first hex letter representing imm
	while(imm >= 0x10)
		imm >>= 4;

	if (imm < 0xa)
		return false;
	else	// this need 0 prefix
		return true;
}

static void printImm(MCInst *MI, SStream *O, int64_t imm, bool positive)
{
	if (positive) {
		// always print this number in positive form
		if (MI->csh->syntax == CS_OPT_SYNTAX_MASM) {
			if (imm < 0) {
				if (MI->op1_size) {
					switch(MI->op1_size) {
						default:
							break;
						case 1:
							imm &= 0xff;
							break;
						case 2:
							imm &= 0xffff;
							break;
						case 4:
							imm &= 0xffffffff;
							break;
					}
				}

				if (imm == 0x8000000000000000LL)  // imm == -imm
					SStream_concat0(O, "8000000000000000h");
				else if (need_zero_prefix(imm))
					SStream_concat(O, "0%"PRIx64"h", imm);
				else
					SStream_concat(O, "%"PRIx64"h", imm);
			} else {
				if (imm > HEX_THRESHOLD) {
					if (need_zero_prefix(imm))
						SStream_concat(O, "0%"PRIx64"h", imm);
					else
						SStream_concat(O, "%"PRIx64"h", imm);
				} else
					SStream_concat(O, "%"PRIu64, imm);
			}
		} else {	// Intel syntax
			if (imm < 0) {
				if (MI->op1_size) {
					switch(MI->op1_size) {
						default:
							break;
						case 1:
							imm &= 0xff;
							break;
						case 2:
							imm &= 0xffff;
							break;
						case 4:
							imm &= 0xffffffff;
							break;
					}
				}

				SStream_concat(O, "0x%"PRIx64, imm);
			} else {
				if (imm > HEX_THRESHOLD)
					SStream_concat(O, "0x%"PRIx64, imm);
				else
					SStream_concat(O, "%"PRIu64, imm);
			}
		}
	} else {
		if (MI->csh->syntax == CS_OPT_SYNTAX_MASM) {
			if (imm < 0) {
				if (imm == 0x8000000000000000LL)  // imm == -imm
					SStream_concat0(O, "8000000000000000h");
				else if (imm < -HEX_THRESHOLD) {
					if (need_zero_prefix(imm))
						SStream_concat(O, "-0%"PRIx64"h", -imm);
					else
						SStream_concat(O, "-%"PRIx64"h", -imm);
				} else
					SStream_concat(O, "-%"PRIu64, -imm);
			} else {
				if (imm > HEX_THRESHOLD) {
					if (need_zero_prefix(imm))
						SStream_concat(O, "0%"PRIx64"h", imm);
					else
						SStream_concat(O, "%"PRIx64"h", imm);
				} else
					SStream_concat(O, "%"PRIu64, imm);
			}
		} else {	// Intel syntax
			if (imm < 0) {
				if (imm == 0x8000000000000000LL)  // imm == -imm
					SStream_concat0(O, "0x8000000000000000");
				else if (imm < -HEX_THRESHOLD)
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
}

// local printOperand, without updating public operands
static void _printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		printImm(MI, O, imm, MI->csh->imm_unsigned);
	}
}

#ifndef CAPSTONE_DIET
// copy & normalize access info
static void get_op_access(cs_struct *h, unsigned int id, uint8_t *access, uint64_t *eflags)
{
#ifndef CAPSTONE_DIET
	uint8_t i;
	const uint8_t *arr = X86_get_op_access(h, id, eflags);

	// initialize access
	memset(access, 0, CS_X86_MAXIMUM_OPERAND_SIZE * sizeof(access[0]));

	if (!arr) {
		access[0] = 0;
		return;
	}

	// copy to access but zero out CS_AC_IGNORE
	for(i = 0; arr[i]; i++) {
		if (arr[i] != CS_AC_IGNORE)
			access[i] = arr[i];
		else
			access[i] = 0;
	}

	// mark the end of array
	access[i] = 0;
#endif
}
#endif

static void printSrcIdx(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *SegReg;
	int reg;

	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif
	}

	SegReg = MCInst_getOperand(MI, Op + 1);
	reg = MCOperand_getReg(SegReg);

	// If this has a segment register, print it.
	if (reg) {
		_printOperand(MI, Op + 1, O);
		if (MI->csh->detail_opt) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_register_map(reg);
		}
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "[");
	set_mem_access(MI, true);
	printOperand(MI, Op, O);
	SStream_concat0(O, "]");
	set_mem_access(MI, false);
}

static void printDstIdx(MCInst *MI, unsigned Op, SStream *O)
{
	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif
	}

	// DI accesses are always ES-based on non-64bit mode
	if (MI->csh->mode != CS_MODE_64) {
		SStream_concat0(O, "es:[");
		if (MI->csh->detail_opt) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_ES;
		}
	} else
		SStream_concat0(O, "[");

	set_mem_access(MI, true);
	printOperand(MI, Op, O);
	SStream_concat0(O, "]");
	set_mem_access(MI, false);
}

static void printSrcIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	MI->x86opsize = 1;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");
	MI->x86opsize = 2;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	MI->x86opsize = 4;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	MI->x86opsize = 8;
	printSrcIdx(MI, OpNo, O);
}

static void printDstIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	MI->x86opsize = 1;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");
	MI->x86opsize = 2;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	MI->x86opsize = 4;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	MI->x86opsize = 8;
	printDstIdx(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);
	MCOperand *SegReg = MCInst_getOperand(MI, Op + 1);
	int reg;

	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + 1, O);
		SStream_concat0(O, ":");
		if (MI->csh->detail_opt) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_register_map(reg);
		}
	}

	SStream_concat0(O, "[");

	if (MCOperand_isImm(DispSpec)) {
		int64_t imm = MCOperand_getImm(DispSpec);
		if (MI->csh->detail_opt)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;

		if (imm < 0)
			printImm(MI, O, arch_masks[MI->csh->mode] & imm, true);
		else
			printImm(MI, O, imm, true);
	}

	SStream_concat0(O, "]");

	if (MI->csh->detail_opt)
		MI->flat_insn->detail->x86.op_count++;

	if (MI->op1_size == 0)
		MI->op1_size = MI->x86opsize;
}

static void printU8Imm(MCInst *MI, unsigned Op, SStream *O)
{
	uint8_t val = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0xff;

	printImm(MI, O, val, true);

	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = val;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = 1;

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif

		MI->flat_insn->detail->x86.op_count++;
	}
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "byte ptr ");
	MI->x86opsize = 1;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "word ptr ");
	MI->x86opsize = 2;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "dword ptr ");
	MI->x86opsize = 4;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	SStream_concat0(O, "qword ptr ");
	MI->x86opsize = 8;
	printMemOffset(MI, OpNo, O);
}

static void printInstruction(MCInst *MI, SStream *O);

void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)
{
	x86_reg reg, reg2;
	enum cs_ac_type access1, access2;

	// printf("opcode = %u\n", MCInst_getOpcode(MI));

	// perhaps this instruction does not need printer
	if (MI->assembly[0]) {
		strncpy(O->buffer, MI->assembly, sizeof(O->buffer));
		return;
	}

	X86_lockrep(MI, O);
	printInstruction(MI, O);

	reg = X86_insn_reg_intel(MCInst_getOpcode(MI), &access1);
	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE] = {0};
#endif

		// first op can be embedded in the asm by llvm.
		// so we have to add the missing register as the first operand
		if (reg) {
			// shift all the ops right to leave 1st slot for this new register op
			memmove(&(MI->flat_insn->detail->x86.operands[1]), &(MI->flat_insn->detail->x86.operands[0]),
					sizeof(MI->flat_insn->detail->x86.operands[0]) * (ARR_SIZE(MI->flat_insn->detail->x86.operands) - 1));
			MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
			MI->flat_insn->detail->x86.operands[0].reg = reg;
			MI->flat_insn->detail->x86.operands[0].size = MI->csh->regsize_map[reg];
			MI->flat_insn->detail->x86.operands[0].access = access1;
			MI->flat_insn->detail->x86.op_count++;
		} else {
			if (X86_insn_reg_intel2(MCInst_getOpcode(MI), &reg, &access1, &reg2, &access2)) {
				MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[0].reg = reg;
				MI->flat_insn->detail->x86.operands[0].size = MI->csh->regsize_map[reg];
				MI->flat_insn->detail->x86.operands[0].access = access1;
				MI->flat_insn->detail->x86.operands[1].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[1].reg = reg2;
				MI->flat_insn->detail->x86.operands[1].size = MI->csh->regsize_map[reg2];
				MI->flat_insn->detail->x86.operands[1].access = access2;
				MI->flat_insn->detail->x86.op_count = 2;
			}
		}

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[0].access = access[0];
		MI->flat_insn->detail->x86.operands[1].access = access[1];
#endif
	}

	if (MI->op1_size == 0 && reg)
		MI->op1_size = MI->csh->regsize_map[reg];
}

/// printPCRelImm - This is used to print an immediate value that ends up
/// being encoded as a pc-relative value.
static void printPCRelImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op) + MI->flat_insn->size + MI->address;
		uint8_t opsize = X86_immediate_size(MI->Opcode, NULL);

		// truncate imm for non-64bit
		if (MI->csh->mode != CS_MODE_64) {
			imm = imm & 0xffffffff;
		}

		printImm(MI, O, imm, true);

		if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
			uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
			// if op_count > 0, then this operand's size is taken from the destination op
			if (MI->flat_insn->detail->x86.op_count > 0)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->flat_insn->detail->x86.operands[0].size;
			else if (opsize > 0)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = opsize;
			else
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->imm_size;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;

#ifndef CAPSTONE_DIET
			get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif

			MI->flat_insn->detail->x86.op_count++;
		}

		if (MI->op1_size == 0)
			MI->op1_size = MI->imm_size;
	}
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);

	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);

		printRegName(O, reg);
		if (MI->csh->detail_opt) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_register_map(reg);
			} else {
#ifndef CAPSTONE_DIET
				uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].reg = X86_register_map(reg);
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->csh->regsize_map[X86_register_map(reg)];

#ifndef CAPSTONE_DIET
				get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif

				MI->flat_insn->detail->x86.op_count++;
			}
		}

		if (MI->op1_size == 0)
			MI->op1_size = MI->csh->regsize_map[X86_register_map(reg)];
	} else if (MCOperand_isImm(Op)) {
		uint8_t encsize;
		int64_t imm = MCOperand_getImm(Op);
		uint8_t opsize = X86_immediate_size(MCInst_getOpcode(MI), &encsize);

		if (opsize == 1)    // print 1 byte immediate in positive form
			imm = imm & 0xff;

		// printf(">>> id = %u\n", MI->flat_insn->id);
		switch(MI->flat_insn->id) {
			default:
				printImm(MI, O, imm, MI->csh->imm_unsigned);
				break;

			case X86_INS_MOVABS:
			case X86_INS_MOV:
				// do not print number in negative form
				printImm(MI, O, imm, true);
				break;

			case X86_INS_IN:
			case X86_INS_OUT:
			case X86_INS_INT:
				// do not print number in negative form
				imm = imm & 0xff;
				printImm(MI, O, imm, true);
				break;

			case X86_INS_LCALL:
			case X86_INS_LJMP:
			case X86_INS_JMP:
				// always print address in positive form
				if (OpNo == 1) {	// ptr16 part
					imm = imm & 0xffff;
					opsize = 2;
				} else
					opsize = 4;
				printImm(MI, O, imm, true);
				break;

			case X86_INS_AND:
			case X86_INS_OR:
			case X86_INS_XOR:
				// do not print number in negative form
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					printImm(MI, O, imm, true);
				else {
					imm = arch_masks[opsize? opsize : MI->imm_size] & imm;
					printImm(MI, O, imm, true);
				}
				break;

			case X86_INS_RET:
			case X86_INS_RETF:
				// RET imm16
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					printImm(MI, O, imm, true);
				else {
					imm = 0xffff & imm;
					printImm(MI, O, imm, true);
				}
				break;
		}

		if (MI->csh->detail_opt) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;
			} else {
#ifndef CAPSTONE_DIET
				uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
				if (opsize > 0) {
					MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = opsize;
					MI->flat_insn->detail->x86.encoding.imm_size = encsize;
				} else if (MI->flat_insn->detail->x86.op_count > 0) {
					if (MI->flat_insn->id != X86_INS_LCALL && MI->flat_insn->id != X86_INS_LJMP) {
						MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size =
							MI->flat_insn->detail->x86.operands[0].size;
					} else
						MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->imm_size;
				} else
					MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->imm_size;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;

#ifndef CAPSTONE_DIET
				get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif

				MI->flat_insn->detail->x86.op_count++;
			}
		}
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)
{
	bool NeedPlus = false;
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op + X86_AddrBaseReg);
	uint64_t ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op + X86_AddrScaleAmt));
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op + X86_AddrIndexReg);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op + X86_AddrDisp);
	MCOperand *SegReg = MCInst_getOperand(MI, Op + X86_AddrSegmentReg);
	int reg;

	if (MI->csh->detail_opt) {
#ifndef CAPSTONE_DIET
		uint8_t access[CS_X86_MAXIMUM_OPERAND_SIZE];
#endif

		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_register_map(MCOperand_getReg(BaseReg));
        if (MCOperand_getReg(IndexReg) != X86_EIZ) {
            MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_register_map(MCOperand_getReg(IndexReg));
        }
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = (int)ScaleVal;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;

#ifndef CAPSTONE_DIET
		get_op_access(MI->csh, MCInst_getOpcode(MI), access, &MI->flat_insn->detail->x86.eflags);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].access = access[MI->flat_insn->detail->x86.op_count];
#endif
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + X86_AddrSegmentReg, O);
		if (MI->csh->detail_opt) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_register_map(reg);
		}
		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "[");

	if (MCOperand_getReg(BaseReg)) {
		_printOperand(MI, Op + X86_AddrBaseReg, O);
		NeedPlus = true;
	}

	if (MCOperand_getReg(IndexReg) && MCOperand_getReg(IndexReg) != X86_EIZ) {
		if (NeedPlus) SStream_concat0(O, " + ");
		_printOperand(MI, Op + X86_AddrIndexReg, O);
		if (ScaleVal != 1)
			SStream_concat(O, "*%u", ScaleVal);
		NeedPlus = true;
	}

	if (MCOperand_isImm(DispSpec)) {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		if (MI->csh->detail_opt)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = DispVal;
		if (DispVal) {
			if (NeedPlus) {
				if (DispVal < 0) {
					SStream_concat0(O, " - ");
					printImm(MI, O, -DispVal, true);
				} else {
					SStream_concat0(O, " + ");
					printImm(MI, O, DispVal, true);
				}
			} else {
				// memory reference to an immediate address
				if (MI->csh->mode == CS_MODE_64)
					MI->op1_size = 8;
				if (DispVal < 0) {
					printImm(MI, O, arch_masks[MI->csh->mode] & DispVal, true);
				} else {
					printImm(MI, O, DispVal, true);
				}
			}

		} else {
			// DispVal = 0
			if (!NeedPlus)	// [0]
				SStream_concat0(O, "0");
		}
	}

	SStream_concat0(O, "]");

	if (MI->csh->detail_opt)
		MI->flat_insn->detail->x86.op_count++;

	if (MI->op1_size == 0)
		MI->op1_size = MI->x86opsize;
}

static void printanymem(MCInst *MI, unsigned OpNo, SStream *O)
{
	switch(MI->Opcode) {
		default: break;
		case X86_LEA16r:
				 MI->x86opsize = 2;
				 break;
		case X86_LEA32r:
		case X86_LEA64_32r:
				 MI->x86opsize = 4;
				 break;
		case X86_LEA64r:
				 MI->x86opsize = 8;
				 break;
#ifndef CAPSTONE_X86_REDUCE
		case X86_BNDCL32rm:
		case X86_BNDCN32rm:
		case X86_BNDCU32rm:
		case X86_BNDSTXmr:
		case X86_BNDLDXrm:
		case X86_BNDCL64rm:
		case X86_BNDCN64rm:
		case X86_BNDCU64rm:
				 MI->x86opsize = 16;
				 break;
#endif
	}

	printMemReference(MI, OpNo, O);
}

#ifdef CAPSTONE_X86_REDUCE
#include "X86GenAsmWriter1_reduce.inc"
#else
#include "X86GenAsmWriter1.inc"
#endif

#include "X86GenRegisterName1.inc"

#endif
