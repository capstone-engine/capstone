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

//===-- XtensaDisassembler.cpp - Disassembler for Xtensa ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the XtensaDisassembler class.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MathExtras.h"
#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../SStream.h"
#include "../../cs_priv.h"
#include "../../utils.h"
#include "priv.h"

#define GET_INSTRINFO_MC_DESC
#include "XtensaGenInstrInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "Xtensa-disassembler"

static const unsigned ARDecoderTable[] = {
	Xtensa_A0,  Xtensa_SP,	Xtensa_A2,  Xtensa_A3, Xtensa_A4,  Xtensa_A5,
	Xtensa_A6,  Xtensa_A7,	Xtensa_A8,  Xtensa_A9, Xtensa_A10, Xtensa_A11,
	Xtensa_A12, Xtensa_A13, Xtensa_A14, Xtensa_A15
};

static DecodeStatus DecodeARRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= ARR_SIZE(ARDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = ARDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned SRDecoderTable[] = { Xtensa_SAR, 3 };

static DecodeStatus DecodeSRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo > 255)
		return MCDisassembler_Fail;

	for (unsigned i = 0; i + 1 < ARR_SIZE(SRDecoderTable); i += 2) {
		if (SRDecoderTable[i + 1] == RegNo) {
			unsigned Reg = SRDecoderTable[i];
			MCOperand_CreateReg0(Inst, (Reg));
			return MCDisassembler_Success;
		}
	}

	return MCDisassembler_Fail;
}

static bool tryAddingSymbolicOperand(int64_t Value, bool isBranch,
				     uint64_t Address, uint64_t Offset,
				     uint64_t InstSize, MCInst *MI,
				     const void *Decoder)
{
	//	return Dis->tryAddingSymbolicOperand(MI, Value, Address, isBranch,
	//					     Offset, /*OpSize=*/0, InstSize);
	return true;
}

static DecodeStatus decodeCallOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(18, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm << 2), 20)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeJumpOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(18, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 18)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeBranchOperand(MCInst *Inst, uint64_t Imm,
					int64_t Address, const void *Decoder)
{
	switch (MCInst_getOpcode(Inst)) {
	case Xtensa_BEQZ:
	case Xtensa_BGEZ:
	case Xtensa_BLTZ:
	case Xtensa_BNEZ:
		CS_ASSERT(isUIntN(12, Imm) && "Invalid immediate");
		if (!tryAddingSymbolicOperand(
			    SignExtend64((Imm), 12) + 4 + Address, true,
			    Address, 0, 3, Inst, Decoder))
			MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 12)));
		break;
	default:
		CS_ASSERT(isUIntN(8, Imm) && "Invalid immediate");
		if (!tryAddingSymbolicOperand(
			    SignExtend64((Imm), 8) + 4 + Address, true, Address,
			    0, 3, Inst, Decoder))
			MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 8)));
	}
	return MCDisassembler_Success;
}

static DecodeStatus decodeL32ROperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(16, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(
		Inst,
		(SignExtend64(((Imm << 2) + 0x40000 + (Address & 0x3)), 17)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm8Operand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(8, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 8)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm8_sh8Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(8, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm << 8), 16)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm12Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(12, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 12)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeUimm4Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(4, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeUimm5Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(5, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm1_16Operand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(4, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (Imm + 1));
	return MCDisassembler_Success;
}

static DecodeStatus decodeShimm1_31Operand(MCInst *Inst, uint64_t Imm,
					   int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(5, Imm) && "Invalid immediate");
	MCOperand_CreateImm0(Inst, (32 - Imm));
	return MCDisassembler_Success;
}

static int64_t TableB4const[16] = { -1, 1,  2,	3,  4,	5,  6,	 7,
				    8,	10, 12, 16, 32, 64, 128, 256 };
static DecodeStatus decodeB4constOperand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(4, Imm) && "Invalid immediate");

	MCOperand_CreateImm0(Inst, (TableB4const[Imm]));
	return MCDisassembler_Success;
}

static int64_t TableB4constu[16] = { 32768, 65536, 2,  3,  4,  5,  6,	7,
				     8,	    10,	   12, 16, 32, 64, 128, 256 };
static DecodeStatus decodeB4constuOperand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(4, Imm) && "Invalid immediate");

	MCOperand_CreateImm0(Inst, (TableB4constu[Imm]));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem8Operand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(12, Imm) && "Invalid immediate");
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 4) & 0xff));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem16Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(12, Imm) && "Invalid immediate");
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 3) & 0x1fe));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem32Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(12, Imm) && "Invalid immediate");
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 2) & 0x3fc));
	return MCDisassembler_Success;
}

/// Read three bytes from the ArrayRef and return 24 bit data
static DecodeStatus readInstruction24(MCInst *MI, uint64_t *SizeOut,
				      const uint8_t *Bytes,
				      const unsigned BytesSize, uint32_t *Insn)
{
	// We want to read exactly 3 Bytes of data.
	if (BytesSize < 3) {
		*SizeOut = 0;
		return MCDisassembler_Fail;
	}

	*Insn = readBytes24(MI, Bytes);
	*SizeOut = 3;
	return MCDisassembler_Success;
}

#include "XtensaGenDisassemblerTables.inc"

FieldFromInstruction(field_from_inst, uint32_t);
DecodeToMCInst(decode_to_MCInst, field_from_inst, uint32_t);
DecodeInstruction(decodeInstruction, field_from_inst, decode_to_MCInst,
		  uint32_t);

static DecodeStatus getInstruction(MCInst *MI, uint64_t *SizeOut,
				   const uint8_t *Bytes, unsigned BytesSize,
				   uint64_t Address)
{
	uint32_t Insn;
	DecodeStatus Result;

	Result = readInstruction24(MI, SizeOut, Bytes, BytesSize, &Insn);
	if (Result == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	Result = decodeInstruction(DecoderTable24, MI, Insn, Address, NULL);
	return Result;
}

DecodeStatus Xtensa_LLVM_getInstruction(MCInst *MI, uint16_t *size16,
					const uint8_t *Bytes,
					unsigned BytesSize, uint64_t Address)
{
	uint64_t size64;
	DecodeStatus status =
		getInstruction(MI, &size64, Bytes, BytesSize, Address);
	CS_ASSERT_RET_VAL(size64 < 0xffff, MCDisassembler_Fail);
	*size16 = size64;
	return status;
}
