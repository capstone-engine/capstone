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
#include "../../MCFixedLenDisassembler.h"
#include "SparcDisassemblerExtension.h"
#include "SparcLinkage.h"
#include "SparcMapping.h"
#include "SparcMCTargetDesc.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "sparc-disassembler"

static const unsigned IntRegDecoderTable[] = {
	Sparc_G0, Sparc_G1, Sparc_G2, Sparc_G3, Sparc_G4, Sparc_G5, Sparc_G6, Sparc_G7,
	Sparc_O0, Sparc_O1, Sparc_O2, Sparc_O3, Sparc_O4, Sparc_O5, Sparc_O6, Sparc_O7,
	Sparc_L0, Sparc_L1, Sparc_L2, Sparc_L3, Sparc_L4, Sparc_L5, Sparc_L6, Sparc_L7,
	Sparc_I0, Sparc_I1, Sparc_I2, Sparc_I3, Sparc_I4, Sparc_I5, Sparc_I6, Sparc_I7
};

static const unsigned FPRegDecoderTable[] = {
	Sparc_F0,	Sparc_F1,	Sparc_F2,	Sparc_F3,	Sparc_F4,	Sparc_F5,	Sparc_F6,	Sparc_F7,
	Sparc_F8,	Sparc_F9,	Sparc_F10, Sparc_F11, Sparc_F12, Sparc_F13, Sparc_F14, Sparc_F15,
	Sparc_F16, Sparc_F17, Sparc_F18, Sparc_F19, Sparc_F20, Sparc_F21, Sparc_F22, Sparc_F23,
	Sparc_F24, Sparc_F25, Sparc_F26, Sparc_F27, Sparc_F28, Sparc_F29, Sparc_F30, Sparc_F31
};

static const unsigned DFPRegDecoderTable[] = {
	Sparc_D0,	Sparc_D16, Sparc_D1,	Sparc_D17, Sparc_D2,	Sparc_D18, Sparc_D3,	Sparc_D19,
	Sparc_D4,	Sparc_D20, Sparc_D5,	Sparc_D21, Sparc_D6,	Sparc_D22, Sparc_D7,	Sparc_D23,
	Sparc_D8,	Sparc_D24, Sparc_D9,	Sparc_D25, Sparc_D10, Sparc_D26, Sparc_D11, Sparc_D27,
	Sparc_D12, Sparc_D28, Sparc_D13, Sparc_D29, Sparc_D14, Sparc_D30, Sparc_D15, Sparc_D31
};

static const unsigned QFPRegDecoderTable[] = {
	Sparc_Q0, Sparc_Q8,  ~0U, ~0U, Sparc_Q1, Sparc_Q9,	~0U, ~0U,
	Sparc_Q2, Sparc_Q10, ~0U, ~0U, Sparc_Q3, Sparc_Q11, ~0U, ~0U,
	Sparc_Q4, Sparc_Q12, ~0U, ~0U, Sparc_Q5, Sparc_Q13, ~0U, ~0U,
	Sparc_Q6, Sparc_Q14, ~0U, ~0U, Sparc_Q7, Sparc_Q15, ~0U, ~0U
};

static const unsigned FCCRegDecoderTable[] = { Sparc_FCC0, Sparc_FCC1, Sparc_FCC2,
					       Sparc_FCC3 };

static const unsigned ASRRegDecoderTable[] = {
	Sparc_Y,	  Sparc_ASR1,  Sparc_ASR2,  Sparc_ASR3,	Sparc_ASR4,  Sparc_ASR5,  Sparc_ASR6,
	Sparc_ASR7,  Sparc_ASR8,  Sparc_ASR9,  Sparc_ASR10, Sparc_ASR11, Sparc_ASR12, Sparc_ASR13,
	Sparc_ASR14, Sparc_ASR15, Sparc_ASR16, Sparc_ASR17, Sparc_ASR18, Sparc_ASR19, Sparc_ASR20,
	Sparc_ASR21, Sparc_ASR22, Sparc_ASR23, Sparc_ASR24, Sparc_ASR25, Sparc_ASR26, Sparc_ASR27,
	Sparc_ASR28, Sparc_ASR29, Sparc_ASR30, Sparc_ASR31
};

static const unsigned PRRegDecoderTable[] = {
	Sparc_TPC,	    Sparc_TNPC,	   Sparc_TSTATE,	Sparc_TT,	     Sparc_TICK,
	Sparc_TBA,	    Sparc_PSTATE,	   Sparc_TL,	Sparc_PIL,	     Sparc_CWP,
	Sparc_CANSAVE, Sparc_CANRESTORE, Sparc_CLEANWIN, Sparc_OTHERWIN, Sparc_WSTATE
};

static const uint16_t IntPairDecoderTable[] = {
	Sparc_G0_G1, Sparc_G2_G3, Sparc_G4_G5, Sparc_G6_G7, Sparc_O0_O1, Sparc_O2_O3,
	Sparc_O4_O5, Sparc_O6_O7, Sparc_L0_L1, Sparc_L2_L3, Sparc_L4_L5, Sparc_L6_L7,
	Sparc_I0_I1, Sparc_I2_I3, Sparc_I4_I5, Sparc_I6_I7,
};

static const unsigned CPRegDecoderTable[] = {
	Sparc_C0,	Sparc_C1,	Sparc_C2,	Sparc_C3,	Sparc_C4,	Sparc_C5,	Sparc_C6,	Sparc_C7,
	Sparc_C8,	Sparc_C9,	Sparc_C10, Sparc_C11, Sparc_C12, Sparc_C13, Sparc_C14, Sparc_C15,
	Sparc_C16, Sparc_C17, Sparc_C18, Sparc_C19, Sparc_C20, Sparc_C21, Sparc_C22, Sparc_C23,
	Sparc_C24, Sparc_C25, Sparc_C26, Sparc_C27, Sparc_C28, Sparc_C29, Sparc_C30, Sparc_C31
};

static const uint16_t CPPairDecoderTable[] = {
	Sparc_C0_C1,   Sparc_C2_C3,	Sparc_C4_C5,   Sparc_C6_C7,	Sparc_C8_C9,   Sparc_C10_C11,
	Sparc_C12_C13, Sparc_C14_C15, Sparc_C16_C17, Sparc_C18_C19, Sparc_C20_C21, Sparc_C22_C23,
	Sparc_C24_C25, Sparc_C26_C27, Sparc_C28_C29, Sparc_C30_C31
};

static DecodeStatus DecodeDisp19(MCInst *Inst, uint32_t ImmVal,
					       uint64_t Address,
					       const void *Decoder)
{
	int64_t BranchTarget = Address + (SignExtend64(ImmVal, 19) * 4);
	MCOperand_CreateImm0(Inst, BranchTarget);
	return MCDisassembler_Success;
}

static DecodeStatus DecodeDisp16(MCInst *Inst, uint32_t ImmVal,
					       uint64_t Address,
					       const void *Decoder)
{
	int64_t BranchTarget = Address + (SignExtend64(ImmVal, 16) * 4);
	MCOperand_CreateImm0(Inst, BranchTarget);
	return MCDisassembler_Success;
}

static DecodeStatus DecodeDisp22(MCInst *Inst, uint32_t ImmVal,
					       uint64_t Address,
					       const void *Decoder)
{
	int64_t BranchTarget = Address + (SignExtend64(ImmVal, 22) * 4);
	MCOperand_CreateImm0(Inst, BranchTarget);
	return MCDisassembler_Success;
}

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
	if (RegNo >= ARR_SIZE(PRRegDecoderTable))
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

static DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size, const uint8_t *Bytes,
			    size_t BytesLen, uint64_t Address, SStream *CStream)
{
	if (BytesLen < 4) {
		return MCDisassembler_Fail;
	}
	uint32_t Insn = readBytes32(Instr, Bytes);

	DecodeStatus Result = MCDisassembler_Fail;
	// Calling the auto-generated decoder function.
	if (Sparc_getFeatureBits(Instr->csh->mode, Sparc_FeatureV9)) {
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
	// Capstone doesn't support symbols.
	return false;
}

static DecodeStatus DecodeCall(MCInst *MI, unsigned insn, uint64_t Address,
			       const void *Decoder)
{
	unsigned Offset = fieldFromInstruction_4(insn, 0, 30);
	int64_t CallTarget = Address + (SignExtend64(Offset, 30) * 4);
	if (!tryAddingSymbolicOperand(CallTarget, false, Address, 0, 30, MI,
				      Decoder))
		MCOperand_CreateImm0(MI, CallTarget);
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSIMM13(MCInst *MI, unsigned insn, uint64_t Address,
				 const void *Decoder)
{
	CS_ASSERT(isUIntN(13, insn));
	MCOperand_CreateImm0(MI, (SignExtend64((insn), 13)));
	return MCDisassembler_Success;
}

DecodeStatus Sparc_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				     size_t ByteLen, MCInst *MI, uint16_t *Size,
				     uint64_t Address, void *Info) {
	uint64_t s = 0;
	DecodeStatus status = getInstruction(MI, &s, Bytes, ByteLen, Address, NULL);
	*Size = (uint16_t) s;
	return status;
}
