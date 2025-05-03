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

//===- SparcDisassembler.cpp - Disassembler for Sparc -----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is part of the Sparc Disassembler.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCDisassembler.h"
#include "SparcLinkage.h"
#include "SparcMapping.h"
#include "SparcMCTargetDesc.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "sparc-disassembler"

typedef MCDisassembler_DecodeStatus DecodeStatus;

/// A disassembler class for Sparc.
DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size, const uint8_t *Bytes,
			    size_t BytesLen, uint64_t Address,
			    SStream *CStream);
;

static MCDisassembler *createSparcDisassembler(const Target *T, MCContext *Ctx)
{
	return new SparcDisassembler(STI, Ctx);
}

extern "C" LLVM_EXTERNAL_VISIBILITY void LLVMInitializeSparcDisassembler()
{
	// Register the disassembler.
	TargetRegistry_RegisterMCDisassembler(getTheSparcTarget(),
					      createSparcDisassembler);
	TargetRegistry_RegisterMCDisassembler(getTheSparcV9Target(),
					      createSparcDisassembler);
	TargetRegistry_RegisterMCDisassembler(getTheSparcelTarget(),
					      createSparcDisassembler);
}

static const unsigned IntRegDecoderTable[] = {
	SP_G0, SP_G1, SP_G2, SP_G3, SP_G4, SP_G5, SP_G6, SP_G7,
	SP_O0, SP_O1, SP_O2, SP_O3, SP_O4, SP_O5, SP_O6, SP_O7,
	SP_L0, SP_L1, SP_L2, SP_L3, SP_L4, SP_L5, SP_L6, SP_L7,
	SP_I0, SP_I1, SP_I2, SP_I3, SP_I4, SP_I5, SP_I6, SP_I7
};

static const unsigned FPRegDecoderTable[] = {
	SP_F0,	SP_F1,	SP_F2,	SP_F3,	SP_F4,	SP_F5,	SP_F6,	SP_F7,
	SP_F8,	SP_F9,	SP_F10, SP_F11, SP_F12, SP_F13, SP_F14, SP_F15,
	SP_F16, SP_F17, SP_F18, SP_F19, SP_F20, SP_F21, SP_F22, SP_F23,
	SP_F24, SP_F25, SP_F26, SP_F27, SP_F28, SP_F29, SP_F30, SP_F31
};

static const unsigned DFPRegDecoderTable[] = {
	SP_D0,	SP_D16, SP_D1,	SP_D17, SP_D2,	SP_D18, SP_D3,	SP_D19,
	SP_D4,	SP_D20, SP_D5,	SP_D21, SP_D6,	SP_D22, SP_D7,	SP_D23,
	SP_D8,	SP_D24, SP_D9,	SP_D25, SP_D10, SP_D26, SP_D11, SP_D27,
	SP_D12, SP_D28, SP_D13, SP_D29, SP_D14, SP_D30, SP_D15, SP_D31
};

static const unsigned QFPRegDecoderTable[] = {
	SP_Q0, SP_Q8,  ~0U, ~0U, SP_Q1, SP_Q9,	~0U, ~0U,
	SP_Q2, SP_Q10, ~0U, ~0U, SP_Q3, SP_Q11, ~0U, ~0U,
	SP_Q4, SP_Q12, ~0U, ~0U, SP_Q5, SP_Q13, ~0U, ~0U,
	SP_Q6, SP_Q14, ~0U, ~0U, SP_Q7, SP_Q15, ~0U, ~0U
};

static const unsigned FCCRegDecoderTable[] = { SP_FCC0, SP_FCC1, SP_FCC2,
					       SP_FCC3 };

static const unsigned ASRRegDecoderTable[] = {
	SP_Y,	  SP_ASR1,  SP_ASR2,  SP_ASR3,	SP_ASR4,  SP_ASR5,  SP_ASR6,
	SP_ASR7,  SP_ASR8,  SP_ASR9,  SP_ASR10, SP_ASR11, SP_ASR12, SP_ASR13,
	SP_ASR14, SP_ASR15, SP_ASR16, SP_ASR17, SP_ASR18, SP_ASR19, SP_ASR20,
	SP_ASR21, SP_ASR22, SP_ASR23, SP_ASR24, SP_ASR25, SP_ASR26, SP_ASR27,
	SP_ASR28, SP_ASR29, SP_ASR30, SP_ASR31
};

static const unsigned PRRegDecoderTable[] = {
	SP_TPC,	    SP_TNPC,	   SP_TSTATE,	SP_TT,	     SP_TICK,
	SP_TBA,	    SP_PSTATE,	   SP_TL,	SP_PIL,	     SP_CWP,
	SP_CANSAVE, SP_CANRESTORE, SP_CLEANWIN, SP_OTHERWIN, SP_WSTATE
};

static const uint16_t IntPairDecoderTable[] = {
	SP_G0_G1, SP_G2_G3, SP_G4_G5, SP_G6_G7, SP_O0_O1, SP_O2_O3,
	SP_O4_O5, SP_O6_O7, SP_L0_L1, SP_L2_L3, SP_L4_L5, SP_L6_L7,
	SP_I0_I1, SP_I2_I3, SP_I4_I5, SP_I6_I7,
};

static const unsigned CPRegDecoderTable[] = {
	SP_C0,	SP_C1,	SP_C2,	SP_C3,	SP_C4,	SP_C5,	SP_C6,	SP_C7,
	SP_C8,	SP_C9,	SP_C10, SP_C11, SP_C12, SP_C13, SP_C14, SP_C15,
	SP_C16, SP_C17, SP_C18, SP_C19, SP_C20, SP_C21, SP_C22, SP_C23,
	SP_C24, SP_C25, SP_C26, SP_C27, SP_C28, SP_C29, SP_C30, SP_C31
};

static const uint16_t CPPairDecoderTable[] = {
	SP_C0_C1,   SP_C2_C3,	SP_C4_C5,   SP_C6_C7,	SP_C8_C9,   SP_C10_C11,
	SP_C12_C13, SP_C14_C15, SP_C16_C17, SP_C18_C19, SP_C20_C21, SP_C22_C23,
	SP_C24_C25, SP_C26_C27, SP_C28_C29, SP_C30_C31
};

static DecodeStatus DecodeIntRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = IntRegDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeI64RegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return DecodeIntRegsRegisterClass(Inst, RegNo, Address, Decoder);
}

// This is used for the type "ptr_rc", which is either IntRegs or I64Regs
// depending on SparcRegisterInfo::getPointerRegClass.
static DecodeStatus DecodePointerLikeRegClass0(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return DecodeIntRegsRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = FPRegDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeDFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = DFPRegDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeQFPRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = QFPRegDecoderTable[RegNo];
	if (Reg == ~0U)
		return MCDisassembler_Fail;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCoprocRegsRegisterClass(MCInst *Inst, unsigned RegNo,
						  uint64_t Address,
						  const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = CPRegDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFCCRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 3)
		return MCDisassembler_Fail;
	MCOperand_CreateReg0(Inst, (FCCRegDecoderTable[RegNo]));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeASRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	MCOperand_CreateReg0(Inst, (ASRRegDecoderTable[RegNo]));
	return MCDisassembler_Success;
}

static DecodeStatus DecodePRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo >= sizeof(PRRegDecoderTable))
		return MCDisassembler_Fail;
	MCOperand_CreateReg0(Inst, (PRRegDecoderTable[RegNo]));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeIntPairRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	DecodeStatus S = MCDisassembler_Success;

	if (RegNo > 31)
		return MCDisassembler_Fail;

	if ((RegNo & 1))
		S = MCDisassembler_SoftFail;

	unsigned RegisterPair = IntPairDecoderTable[RegNo / 2];
	MCOperand_CreateReg0(Inst, (RegisterPair));
	return S;
}

static DecodeStatus DecodeCoprocPairRegisterClass(MCInst *Inst, unsigned RegNo,
						  uint64_t Address,
						  const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned RegisterPair = CPPairDecoderTable[RegNo / 2];
	MCOperand_CreateReg0(Inst, (RegisterPair));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCall(MCInst *Inst, unsigned insn, uint64_t Address,
			       const void *Decoder);
static DecodeStatus DecodeSIMM13(MCInst *Inst, unsigned insn, uint64_t Address,
				 const void *Decoder);

#include "SparcGenDisassemblerTables.inc"

/// Read four bytes from the ArrayRef and return 32 bit word.
static DecodeStatus readInstruction32(const uint8_t *Bytes, size_t BytesLen,
				      uint64_t Address, uint64_t *Size,
				      uint32_t *Insn, bool IsLittleEndian)
{
	// We want to read exactly 4 Bytes of data.
	if (BytesLen < 4) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	Insn = IsLittleEndian ? (Bytes[0] << 0) | (Bytes[1] << 8) |
					(Bytes[2] << 16) | (Bytes[3] << 24) :
				(Bytes[3] << 0) | (Bytes[2] << 8) |
					(Bytes[1] << 16) | (Bytes[0] << 24);

	return MCDisassembler_Success;
}

DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size, const uint8_t *Bytes,
			    size_t BytesLen, uint64_t Address, SStream *CStream)
{
	uint32_t Insn;
	bool isLittleEndian = getContext().getAsmInfo()->isLittleEndian();
	DecodeStatus Result =
		readInstruction32(Bytes, Address, Size, Insn, isLittleEndian);
	if (Result == MCDisassembler_Fail)
		return MCDisassembler_Fail;

	// Calling the auto-generated decoder function.

	if (STI.hasFeature(Sparc_FeatureV9)) {
		Result = decodeInstruction_4(DecoderTableSparcV932, Instr, Insn,
					     Address, NULL);
	} else {
		Result = decodeInstruction_4(DecoderTableSparcV832, Instr, Insn,
					     Address, NULL);
	}
	if (Result != MCDisassembler_Fail) {
		*Size = 4;
		return Result;
	}

	Result = decodeInstruction_4(DecoderTableSparc32, Instr, Insn, Address,
				     NULL);

	if (Result != MCDisassembler_Fail) {
		*Size = 4;
		return Result;
	}

	return MCDisassembler_Fail;
}

static bool tryAddingSymbolicOperand(int64_t Value, bool isBranch,
				     uint64_t Address, uint64_t Offset,
				     uint64_t Width, MCInst *MI,
				     const void *Decoder)
{
	return Decoder->tryAddingSymbolicOperand(MI, Value, Address, isBranch,
						 Offset, Width, /*InstSize=*/4);
}

static DecodeStatus DecodeCall(MCInst *MI, unsigned insn, uint64_t Address,
			       const void *Decoder)
{
	unsigned tgt = fieldFromInstruction_4(insn, 0, 30);
	tgt <<= 2;
	if (!tryAddingSymbolicOperand(tgt + Address, false, Address, 0, 30, MI,
				      Decoder))
		MCOperand_CreateImm0(MI, (tgt));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSIMM13(MCInst *MI, unsigned insn, uint64_t Address,
				 const void *Decoder)
{
	CS_ASSERT(isUIntN(13, insn));
	MCOperand_CreateImm0(MI, (SignExtend64((insn), 13)));
	return MCDisassembler_Success;
}
