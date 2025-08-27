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

//===- ARCDisassembler.cpp - Disassembler for ARC ---------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is part of the ARC Disassembler.
///
//===----------------------------------------------------------------------===//

#ifdef CAPSTONE_HAS_ARC

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MathExtras.h"
#include "../../utils.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "arc-disassembler"

/// A disassembler class for ARC.
static DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size,
				   const uint8_t *Bytes, size_t BytesLen,
				   uint64_t Address, SStream *CStream);

// end anonymous namespace

static bool readInstruction32(const uint8_t *Bytes, size_t BytesLen,
			      uint64_t Address, uint64_t *Size, uint32_t *Insn)
{
	*Size = 4;
	// Read 2 16-bit values, but swap hi/lo parts.
	*Insn = (Bytes[0] << 16) | (Bytes[1] << 24) | (Bytes[2] << 0) |
		(Bytes[3] << 8);
	return true;
}

static bool readInstruction64(const uint8_t *Bytes, size_t BytesLen,
			      uint64_t Address, uint64_t *Size, uint64_t *Insn)
{
	*Size = 8;
	*Insn = ((uint64_t)Bytes[0] << 16) | ((uint64_t)Bytes[1] << 24) |
		((uint64_t)Bytes[2] << 0) | ((uint64_t)Bytes[3] << 8) |
		((uint64_t)Bytes[4] << 48) | ((uint64_t)Bytes[5] << 56) |
		((uint64_t)Bytes[6] << 32) | ((uint64_t)Bytes[7] << 40);
	return true;
}

static bool readInstruction48(const uint8_t *Bytes, size_t BytesLen,
			      uint64_t Address, uint64_t *Size, uint64_t *Insn)
{
	*Size = 6;
	*Insn = ((uint64_t)Bytes[0] << 0) | ((uint64_t)Bytes[1] << 8) |
		((uint64_t)Bytes[2] << 32) | ((uint64_t)Bytes[3] << 40) |
		((uint64_t)Bytes[4] << 16) | ((uint64_t)Bytes[5] << 24);
	return true;
}

static bool readInstruction16(const uint8_t *Bytes, size_t BytesLen,
			      uint64_t Address, uint64_t *Size, uint32_t *Insn)
{
	*Size = 2;
	*Insn = (Bytes[0] << 0) | (Bytes[1] << 8);
	return true;
}

#define DECLARE_DecodeSignedOperand(B) \
	static DecodeStatus CONCAT(DecodeSignedOperand, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder);
DECLARE_DecodeSignedOperand(11);
DECLARE_DecodeSignedOperand(9);
DECLARE_DecodeSignedOperand(10);
DECLARE_DecodeSignedOperand(12);

#define DECLARE_DecodeFromCyclicRange(B) \
	static DecodeStatus CONCAT(DecodeFromCyclicRange, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder);
DECLARE_DecodeFromCyclicRange(3);

#define DECLARE_DecodeBranchTargetS(B) \
	static DecodeStatus CONCAT(DecodeBranchTargetS, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder);
DECLARE_DecodeBranchTargetS(8);
DECLARE_DecodeBranchTargetS(10);
DECLARE_DecodeBranchTargetS(7);
DECLARE_DecodeBranchTargetS(13);
DECLARE_DecodeBranchTargetS(21);
DECLARE_DecodeBranchTargetS(25);
DECLARE_DecodeBranchTargetS(9);

static DecodeStatus DecodeMEMrs9(MCInst *, unsigned, uint64_t, const void *);

static DecodeStatus DecodeLdLImmInstruction(MCInst *, uint64_t, uint64_t,
					    const void *);

static DecodeStatus DecodeStLImmInstruction(MCInst *, uint64_t, uint64_t,
					    const void *);

static DecodeStatus DecodeLdRLImmInstruction(MCInst *, uint64_t, uint64_t,
					     const void *);

static DecodeStatus DecodeSOPwithRS12(MCInst *, uint64_t, uint64_t,
				      const void *);

static DecodeStatus DecodeSOPwithRU6(MCInst *, uint64_t, uint64_t,
				     const void *);

static DecodeStatus DecodeCCRU6Instruction(MCInst *, uint64_t, uint64_t,
					   const void *);

static DecodeStatus DecodeMoveHRegInstruction(MCInst *Inst, uint64_t, uint64_t,
					      const void *);

#define GET_REGINFO_ENUM
#include "ARCGenRegisterInfo.inc"

static const uint16_t GPR32DecoderTable[] = {
	ARC_R0,	 ARC_R1,    ARC_R2,  ARC_R3,   ARC_R4,	ARC_R5,	 ARC_R6,
	ARC_R7,	 ARC_R8,    ARC_R9,  ARC_R10,  ARC_R11, ARC_R12, ARC_R13,
	ARC_R14, ARC_R15,   ARC_R16, ARC_R17,  ARC_R18, ARC_R19, ARC_R20,
	ARC_R21, ARC_R22,   ARC_R23, ARC_R24,  ARC_R25, ARC_GP,	 ARC_FP,
	ARC_SP,	 ARC_ILINK, ARC_R30, ARC_BLINK
};

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo >= 32) {
		;
		return MCDisassembler_Fail;
	}

	unsigned Reg = GPR32DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGBR32ShortRegister(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	// Enumerates registers from ranges [r0-r3],[r12-r15].
	if (RegNo > 3)
		RegNo += 8; // 4 for r12, etc...

	return DecodeGPR32RegisterClass(Inst, RegNo, Address, Decoder);
}

#include "ARCGenDisassemblerTables.inc"

static unsigned decodeCField(unsigned Insn)
{
	return fieldFromInstruction_4(Insn, 6, 6);
}

static unsigned decodeBField(unsigned Insn)
{
	return (fieldFromInstruction_4(Insn, 12, 3) << 3) |
	       fieldFromInstruction_4(Insn, 24, 3);
}

static unsigned decodeAField(unsigned Insn)
{
	return fieldFromInstruction_4(Insn, 0, 6);
}

static DecodeStatus DecodeMEMrs9(MCInst *Inst, unsigned Insn, uint64_t Address,
				 const void *Decoder)
{
	// We have the 9-bit immediate in the low bits, 6-bit register in high bits.
	unsigned S9 = Insn & 0x1ff;
	unsigned R = (Insn & (0x7fff & ~0x1ff)) >> 9;
	if (DecodeGPR32RegisterClass(Inst, R, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}
	MCOperand_CreateImm0(Inst, (SignExtend32((S9), 9)));
	return MCDisassembler_Success;
}

static void DecodeSymbolicOperandOff(MCInst *Inst, uint64_t Address,
				     uint64_t Offset, const void *Decoder)
{
	uint64_t NextAddress = Address + Offset;

	MCOperand_CreateImm0(Inst, (NextAddress));
}

#define DEFINE_DecodeBranchTargetS(B) \
	static DecodeStatus CONCAT(DecodeBranchTargetS, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(B > 0 && "field is empty"); \
		DecodeSymbolicOperandOff(Inst, Address, \
					 SignExtend32((InsnS), B), Decoder); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeBranchTargetS(8);
DEFINE_DecodeBranchTargetS(10);
DEFINE_DecodeBranchTargetS(7);
DEFINE_DecodeBranchTargetS(13);
DEFINE_DecodeBranchTargetS(21);
DEFINE_DecodeBranchTargetS(25);
DEFINE_DecodeBranchTargetS(9);

#define DEFINE_DecodeSignedOperand(B) \
	static DecodeStatus CONCAT(DecodeSignedOperand, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(B > 0 && "field is empty"); \
		MCOperand_CreateImm0( \
			Inst, SignExtend32(maskTrailingOnes32(B) & InsnS, B)); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeSignedOperand(11);
DEFINE_DecodeSignedOperand(9);
DEFINE_DecodeSignedOperand(10);
DEFINE_DecodeSignedOperand(12);

#define DEFINE_DecodeFromCyclicRange(B) \
	static DecodeStatus CONCAT(DecodeFromCyclicRange, \
				   B)(MCInst * Inst, unsigned InsnS, \
				      uint64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(B > 0 && "field is empty"); \
		const unsigned max = (1u << B) - 1; \
		MCOperand_CreateImm0(Inst, (InsnS < max ? (int)(InsnS) : -1)); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeFromCyclicRange(3);

static DecodeStatus DecodeStLImmInstruction(MCInst *Inst, uint64_t Insn,
					    uint64_t Address,
					    const void *Decoder)
{
	unsigned SrcC, DstB, LImm;
	DstB = decodeBField(Insn);
	if (DstB != 62) {
		return MCDisassembler_Fail;
	}
	SrcC = decodeCField(Insn);
	if (DecodeGPR32RegisterClass(Inst, SrcC, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}
	LImm = (Insn >> 32);
	MCOperand_CreateImm0(Inst, (LImm));
	MCOperand_CreateImm0(Inst, (0));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLdLImmInstruction(MCInst *Inst, uint64_t Insn,
					    uint64_t Address,
					    const void *Decoder)
{
	unsigned DstA, SrcB, LImm;
	;
	SrcB = decodeBField(Insn);
	if (SrcB != 62) {
		;
		return MCDisassembler_Fail;
	}
	DstA = decodeAField(Insn);
	if (DecodeGPR32RegisterClass(Inst, DstA, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}
	LImm = (Insn >> 32);
	MCOperand_CreateImm0(Inst, (LImm));
	MCOperand_CreateImm0(Inst, (0));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLdRLImmInstruction(MCInst *Inst, uint64_t Insn,
					     uint64_t Address,
					     const void *Decoder)
{
	unsigned DstA, SrcB;
	;
	DstA = decodeAField(Insn);
	if (DecodeGPR32RegisterClass(Inst, DstA, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}
	SrcB = decodeBField(Insn);
	if (DecodeGPR32RegisterClass(Inst, SrcB, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}
	if (decodeCField(Insn) != 62) {
		;
		return MCDisassembler_Fail;
	}
	MCOperand_CreateImm0(Inst, ((uint32_t)(Insn >> 32)));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeRegisterOrImm(MCInst *Inst, uint64_t Address,
					const void *Decoder, uint64_t RegNum,
					uint64_t Value)
{
	if (30 == RegNum) {
		MCOperand_CreateImm0(Inst, (Value));
		return MCDisassembler_Success;
	}
	return DecodeGPR32RegisterClass(Inst, RegNum, Address, Decoder);
}

static DecodeStatus DecodeMoveHRegInstruction(MCInst *Inst, uint64_t Insn,
					      uint64_t Address,
					      const void *Decoder)
{
	;

	uint64_t H = fieldFromInstruction_8(Insn, 5, 3) |
		     (fieldFromInstruction_8(Insn, 0, 2) << 3);
	uint64_t G = fieldFromInstruction_8(Insn, 8, 3) |
		     (fieldFromInstruction_8(Insn, 3, 2) << 3);

	if (MCDisassembler_Success !=
	    DecodeRegisterOrImm(Inst, Address, Decoder, G, 0))
		return MCDisassembler_Fail;

	return DecodeRegisterOrImm(Inst, Address, Decoder, H, Insn >> 16u);
}

static DecodeStatus DecodeCCRU6Instruction(MCInst *Inst, uint64_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	unsigned DstB;
	;
	DstB = decodeBField(Insn);
	if (DecodeGPR32RegisterClass(Inst, DstB, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}

	uint64_t U6Field = fieldFromInstruction_8(Insn, 6, 6);
	MCOperand_CreateImm0(Inst, (U6Field));
	uint64_t CCField = fieldFromInstruction_8(Insn, 0, 4);
	MCOperand_CreateImm0(Inst, (CCField));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSOPwithRU6(MCInst *Inst, uint64_t Insn,
				     uint64_t Address, const void *Decoder)
{
	unsigned DstB = decodeBField(Insn);
	if (DecodeGPR32RegisterClass(Inst, DstB, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}

	uint64_t U6 = fieldFromInstruction_8(Insn, 6, 6);
	MCOperand_CreateImm0(Inst, (U6));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSOPwithRS12(MCInst *Inst, uint64_t Insn,
				      uint64_t Address, const void *Decoder)
{
	unsigned DstB = decodeBField(Insn);
	if (DecodeGPR32RegisterClass(Inst, DstB, Address, Decoder) ==
	    MCDisassembler_Fail) {
		return MCDisassembler_Fail;
	}

	uint64_t Lower = fieldFromInstruction_8(Insn, 6, 6);
	uint64_t Upper = fieldFromInstruction_8(Insn, 0, 5);
	uint64_t Sign = fieldFromInstruction_8(Insn, 5, 1) ? -1 : 1;
	uint64_t Result = Sign * ((Upper << 6) + Lower);
	MCOperand_CreateImm0(Inst, (Result));
	return MCDisassembler_Success;
}

static DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size,
				   const uint8_t *Bytes, size_t BytesLen,
				   uint64_t Address, SStream *cStream)
{
	DecodeStatus Result;
	if (BytesLen < 2) {
		*Size = 0;
		return MCDisassembler_Fail;
	}
	uint8_t DecodeByte = (Bytes[1] & 0xF7) >> 3;
	// 0x00 -> 0x07 are 32-bit instructions.
	// 0x08 -> 0x1F are 16-bit instructions.
	if (DecodeByte < 0x08) {
		// 32-bit instruction.
		if (BytesLen < 4) {
			// Did we decode garbage?
			*Size = 0;
			return MCDisassembler_Fail;
		}
		if (BytesLen >= 8) {
			// Attempt to decode 64-bit instruction.
			uint64_t Insn64;
			if (!readInstruction64(Bytes, BytesLen, Address, Size,
					       &Insn64))
				return MCDisassembler_Fail;
			Result = decodeInstruction_8(DecoderTable64, Instr,
						     Insn64, Address, NULL);
			if (MCDisassembler_Success == Result) {
				;
				return Result;
			};
		}
		uint32_t Insn32;
		if (!readInstruction32(Bytes, BytesLen, Address, Size,
				       &Insn32)) {
			return MCDisassembler_Fail;
		}
		// Calling the auto-generated decoder function.
		return decodeInstruction_4(DecoderTable32, Instr, Insn32,
					   Address, NULL);
	} else {
		if (BytesLen >= 6) {
			// Attempt to treat as instr. with limm data.
			uint64_t Insn48;
			if (!readInstruction48(Bytes, BytesLen, Address, Size,
					       &Insn48))
				return MCDisassembler_Fail;
			Result = decodeInstruction_8(DecoderTable48, Instr,
						     Insn48, Address, NULL);
			if (MCDisassembler_Success == Result) {
				;
				return Result;
			};
		}

		uint32_t Insn16;
		if (!readInstruction16(Bytes, BytesLen, Address, Size, &Insn16))
			return MCDisassembler_Fail;

		// Calling the auto-generated decoder function.
		return decodeInstruction_2(DecoderTable16, Instr, Insn16,
					   Address, NULL);
	}
}

DecodeStatus ARC_LLVM_getInstruction(MCInst *MI, uint64_t *Size,
				     const uint8_t *Bytes, size_t BytesLen,
				     uint64_t Address, SStream *CS)
{
	return getInstruction(MI, Size, Bytes, BytesLen, Address, CS);
}

#endif