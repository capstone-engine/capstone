//===- AArch64Disassembler.cpp - Disassembler for AArch64 ISA -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the functions necessary to decode AArch64 instruction
// bitpatterns into MCInsts (with the help of TableGenerated information from
// the instruction definitions).
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>	// DEBUG
#include <stdlib.h>

#include "../../cs_priv.h"

#include "../../SubtargetFeature.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"

#include "AArch64BaseInfo.h"

// Forward-declarations used in the auto-generated files.
static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus
DecodeGPR64xspRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus
DecodeGPR32wspRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeFPR8RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeFPR16RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeFPR32RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeFPR64RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeFPR64LoRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeFPR128RegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeFPR128LoRegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeGPR64noxzrRegisterClass(MCInst *Inst,
		unsigned RegNo,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeDPairRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeQPairRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeDTripleRegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeQTripleRegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeDQuadRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeQQuadRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeAddrRegExtendOperand(MCInst *Inst,
		unsigned OptionHiS,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeBitfield32ImmOperand(MCInst *Inst,
		unsigned Imm6Bits,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeCVT32FixedPosOperand(MCInst *Inst,
		unsigned Imm6Bits,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeFPZeroOperand(MCInst *Inst,
		unsigned RmBits,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeShiftRightImm8(MCInst *Inst, unsigned Val,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeShiftRightImm16(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeShiftRightImm32(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeShiftRightImm64(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeShiftLeftImm8(MCInst *Inst, unsigned Val,
		uint64_t Address, void *Decoder);
static DecodeStatus DecodeShiftLeftImm16(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeShiftLeftImm32(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeShiftLeftImm64(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeMoveWideImmOperand(MCInst *Inst,
		unsigned FullImm,
		uint64_t Address,
		void *Decoder, int RegWidth);

static DecodeStatus DecodeLogicalImmOperand(MCInst *Inst,
		unsigned Bits,
		uint64_t Address,
		void *Decoder, int RegWidth);

static DecodeStatus DecodeRegExtendOperand(MCInst *Inst,
		unsigned ShiftAmount,
		uint64_t Address,
		void *Decoder);

static DecodeStatus
DecodeNeonMovImmShiftOperand(MCInst *Inst, unsigned ShiftAmount,
		uint64_t Address, void *Decoder, A64SE_ShiftExtSpecifiers Ext, bool IsHalf);

static DecodeStatus Decode32BitShiftOperand(MCInst *Inst,
		unsigned ShiftAmount,
		uint64_t Address,
		void *Decoder);
static DecodeStatus DecodeBitfieldInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeFMOVLaneInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeLDSTPairInstruction(MCInst *Inst,
		unsigned Insn,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeLoadPairExclusiveInstruction(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeNamedImmOperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder, NamedImmMapper *N);

static DecodeStatus
DecodeSysRegOperand(SysRegMapper *InstMapper,
		MCInst *Inst, unsigned Val,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeMRSOperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeMSROperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeSingleIndexedInstruction(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeVLDSTPostInstruction(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeVLDSTLanePostInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder);

static DecodeStatus DecodeSHLLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder);

static bool Check(DecodeStatus *Out, DecodeStatus In);

#define GET_SUBTARGETINFO_ENUM
#include "AArch64GenSubtargetInfo.inc"

// Hacky: enable all features for disassembler
static uint64_t getFeatureBits(void)
{
	// enable all features
	return -1;
}

#include "AArch64GenDisassemblerTables.inc"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "AArch64GenRegisterInfo.inc"

static bool Check(DecodeStatus *Out, DecodeStatus In)
{
	switch (In) {
		case MCDisassembler_Success:
			// Out stays the same.
			return true;
		case MCDisassembler_SoftFail:
			*Out = In;
			return true;
		case MCDisassembler_Fail:
			*Out = In;
			return false;
		default:
			return false;	// never reach
	}
}

#define GET_REGINFO_MC_DESC
#include "AArch64GenRegisterInfo.inc"
void AArch64_init(MCRegisterInfo *MRI)
{
	  /*
	  RI->InitMCRegisterInfo(AArch64RegDesc, 228,
	  RA, PC,
	  AArch64MCRegisterClasses, 15,
	  AArch64RegUnitRoots, 66,
	  AArch64RegDiffLists,
	  AArch64RegStrings,
	  AArch64SubRegIdxLists, 6,
	   AArch64SubRegIdxRanges,   AArch64RegEncodingTable);
	  */

	/*
	RI->InitMCRegisterInfo(AArch64RegDesc, 420,
			RA, PC,
			AArch64MCRegisterClasses, 61,
			AArch64RegUnitRoots, 66,
			AArch64RegDiffLists,
			AArch64RegStrings,
			AArch64SubRegIdxLists, 53,
			AArch64SubRegIdxRanges, AArch64RegEncodingTable);
	*/

	MCRegisterInfo_InitMCRegisterInfo(MRI, AArch64RegDesc, 420,
			0, 0, 
			AArch64MCRegisterClasses, 61,
			0, 0, 
			AArch64RegDiffLists,
			0, 
			AArch64SubRegIdxLists, 53,
			0);
}


static DecodeStatus _getInstruction(MCInst *MI,
		const uint8_t *code, size_t code_len,
		uint16_t *Size,
		uint64_t Address, MCRegisterInfo *MRI)
{
	if (code_len < 4) {
		// not enough data
		*Size = 0;
		return MCDisassembler_Fail;
	}

	// Encoded as a small-endian 32-bit word in the stream.
	uint32_t insn = (code[3] << 24) | (code[2] << 16) |
		(code[1] <<  8) | (code[0] <<  0);

	//printf("insn: %u\n", insn);
	// Calling the auto-generated decoder function.
	DecodeStatus result = decodeInstruction(DecoderTableA6432, MI, insn, Address, MRI);
	//printf("result: %u\n", result);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	*Size = 0;
	return MCDisassembler_Fail;
}

bool AArch64_getInstruction(csh ud, unsigned char *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	DecodeStatus status = _getInstruction(instr,
			code, code_len,
			size,
			address, (MCRegisterInfo *)info);

	return status == MCDisassembler_Success;
}

static unsigned getReg(MCRegisterInfo *MRI, unsigned RC, unsigned RegNo)
{
	MCRegisterClass *rc = MCRegisterInfo_getRegClass(MRI, RC);
	return rc->RegsBegin[RegNo];
}

static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_GPR64RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeGPR64xspRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_GPR64xspRegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_GPR32RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeGPR32wspRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_GPR32wspRegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeFPR8RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_FPR8RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeFPR16RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_FPR16RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}


static DecodeStatus
DecodeFPR32RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_FPR32RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeFPR64RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_FPR64RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeFPR64LoRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 15)
		return MCDisassembler_Fail;

	return DecodeFPR64RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus
DecodeFPR128RegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_FPR128RegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus
DecodeFPR128LoRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	if (RegNo > 15)
		return MCDisassembler_Fail;

	return DecodeFPR128RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeGPR64noxzrRegisterClass(MCInst *Inst,
		unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	if (RegNo > 30)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, AArch64_GPR64noxzrRegClassID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeRegisterClassByID(MCInst *Inst, unsigned RegNo,
		unsigned RegID,
		void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	uint16_t Register = getReg(Decoder, RegID, RegNo);
	MCInst_addOperand(Inst, MCOperand_CreateReg(Register));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeDPairRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_DPairRegClassID,
			Decoder);
}

static DecodeStatus DecodeQPairRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_QPairRegClassID,
			Decoder);
}

static DecodeStatus DecodeDTripleRegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_DTripleRegClassID,
			Decoder);
}

static DecodeStatus DecodeQTripleRegisterClass(MCInst *Inst,
		unsigned RegNo, uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_QTripleRegClassID,
			Decoder);
}

static DecodeStatus DecodeDQuadRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_DQuadRegClassID,
			Decoder);
}

static DecodeStatus DecodeQQuadRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address,
		void *Decoder)
{
	return DecodeRegisterClassByID(Inst, RegNo, AArch64_QQuadRegClassID,
			Decoder);
}

static DecodeStatus DecodeAddrRegExtendOperand(MCInst *Inst,
		unsigned OptionHiS,
		uint64_t Address,
		void *Decoder)
{
	// Option{1} must be 1. OptionHiS is made up of {Option{2}, Option{1},
	// S}. Hence we want to check bit 1.
	if (!(OptionHiS & 2))
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(OptionHiS));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBitfield32ImmOperand(MCInst *Inst,
		unsigned Imm6Bits,
		uint64_t Address,
		void *Decoder)
{
	// In the 32-bit variant, bit 6 must be zero. I.e. the immediate must be
	// between 0 and 31.
	if (Imm6Bits > 31)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Imm6Bits));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCVT32FixedPosOperand(MCInst *Inst,
		unsigned Imm6Bits,
		uint64_t Address,
		void *Decoder)
{
	// 1 <= Imm <= 32. Encoded as 64 - Imm so: 63 >= Encoded >= 32.
	if (Imm6Bits < 32)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Imm6Bits));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPZeroOperand(MCInst *Inst,
		unsigned RmBits, uint64_t Address, void *Decoder)
{
	// Any bits are valid in the instruction (they're architecturally ignored),
	// but a code generator should insert 0.
	MCInst_addOperand(Inst, MCOperand_CreateImm(0));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRightImm8(MCInst *Inst,
		unsigned Val, uint64_t Address, void *Decoder)
{
	MCInst_addOperand(Inst, MCOperand_CreateImm(8 - Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRightImm16(MCInst *Inst,
		unsigned Val, uint64_t Address, void *Decoder)
{
	MCInst_addOperand(Inst, MCOperand_CreateImm(16 - Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRightImm32(MCInst *Inst,
		unsigned Val, uint64_t Address, void *Decoder)
{
	MCInst_addOperand(Inst, MCOperand_CreateImm(32 - Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRightImm64(MCInst *Inst,
		unsigned Val, uint64_t Address, void *Decoder)
{
	MCInst_addOperand(Inst, MCOperand_CreateImm(64 - Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftLeftImm8(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	if (Val > 7)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftLeftImm16(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	if (Val > 15)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftLeftImm32(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	if (Val > 31)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftLeftImm64(MCInst *Inst, unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	if (Val > 63)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Val));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMoveWideImmOperand(MCInst *Inst,
		unsigned FullImm,
		uint64_t Address,
		void *Decoder, int RegWidth)
{
	unsigned Imm16 = FullImm & 0xffff;
	unsigned Shift = FullImm >> 16;

	if (RegWidth == 32 && Shift > 1) return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Imm16));
	MCInst_addOperand(Inst, MCOperand_CreateImm(Shift));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLogicalImmOperand(MCInst *Inst,
		unsigned Bits,
		uint64_t Address,
		void *Decoder, int RegWidth)
{
	uint64_t Imm;
	if (!A64Imms_isLogicalImmBits(RegWidth, Bits, &Imm))
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(Bits));
	return MCDisassembler_Success;
}


static DecodeStatus DecodeRegExtendOperand(MCInst *Inst,
		unsigned ShiftAmount,
		uint64_t Address,
		void *Decoder)
{
	// Only values 0-4 are valid for this 3-bit field
	if (ShiftAmount > 4)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(ShiftAmount));
	return MCDisassembler_Success;
}

static DecodeStatus Decode32BitShiftOperand(MCInst *Inst,
		unsigned ShiftAmount,
		uint64_t Address,
		void *Decoder)
{
	// Only values below 32 are valid for a 32-bit register
	if (ShiftAmount > 31)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(ShiftAmount));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBitfieldInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	unsigned Rd = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned ImmS = fieldFromInstruction(Insn, 10, 6);
	unsigned ImmR = fieldFromInstruction(Insn, 16, 6);
	unsigned SF = fieldFromInstruction(Insn, 31, 1);

	// Undef for 0b11 just in case it occurs. Don't want the compiler to optimise
	// out assertions that it thinks should never be hit.
	enum OpcTypes { SBFM = 0, BFM, UBFM, Undef } Opc;
	Opc = (enum OpcTypes)fieldFromInstruction(Insn, 29, 2);

	if (!SF) {
		// ImmR and ImmS must be between 0 and 31 for 32-bit instructions.
		if (ImmR > 31 || ImmS > 31)
			return MCDisassembler_Fail;
	}

	if (SF) {
		DecodeGPR64RegisterClass(Inst, Rd, Address, Decoder);
		// BFM MCInsts use Rd as a source too.
		if (Opc == BFM) DecodeGPR64RegisterClass(Inst, Rd, Address, Decoder);
		DecodeGPR64RegisterClass(Inst, Rn, Address, Decoder);
	} else {
		DecodeGPR32RegisterClass(Inst, Rd, Address, Decoder);
		// BFM MCInsts use Rd as a source too.
		if (Opc == BFM) DecodeGPR32RegisterClass(Inst, Rd, Address, Decoder);
		DecodeGPR32RegisterClass(Inst, Rn, Address, Decoder);
	}

	// ASR and LSR have more specific patterns so they won't get here:
	//assert(!(ImmS == 31 && !SF && Opc != BFM)
	//       && "shift should have used auto decode");
	//assert(!(ImmS == 63 && SF && Opc != BFM)
	//       && "shift should have used auto decode");

	// Extension instructions similarly:
	if (Opc == SBFM && ImmR == 0) {
		//assert((ImmS != 7 && ImmS != 15) && "extension got here");
		//assert((ImmS != 31 || SF == 0) && "extension got here");
	} else if (Opc == UBFM && ImmR == 0) {
		//assert((SF != 0 || (ImmS != 7 && ImmS != 15)) && "extension got here");
	}

	if (Opc == UBFM) {
		// It might be a LSL instruction, which actually takes the shift amount
		// itself as an MCInst operand.
		if (SF && (ImmS + 1) % 64 == ImmR) {
			MCInst_setOpcode(Inst, AArch64_LSLxxi);
			MCInst_addOperand(Inst, MCOperand_CreateImm(63 - ImmS));
			return MCDisassembler_Success;
		} else if (!SF && (ImmS + 1) % 32 == ImmR) {
			MCInst_setOpcode(Inst, AArch64_LSLwwi);
			MCInst_addOperand(Inst, MCOperand_CreateImm(31 - ImmS));
			return MCDisassembler_Success;
		}
	}

	// Otherwise it's definitely either an extract or an insert depending on which
	// of ImmR or ImmS is larger.
	unsigned ExtractOp = 0, InsertOp = 0;
	switch (Opc) {
		default: break;	// never reach
		case SBFM:
				 ExtractOp = SF ? AArch64_SBFXxxii : AArch64_SBFXwwii;
				 InsertOp = SF ? AArch64_SBFIZxxii : AArch64_SBFIZwwii;
				 break;
		case BFM:
				 ExtractOp = SF ? AArch64_BFXILxxii : AArch64_BFXILwwii;
				 InsertOp = SF ? AArch64_BFIxxii : AArch64_BFIwwii;
				 break;
		case UBFM:
				 ExtractOp = SF ? AArch64_UBFXxxii : AArch64_UBFXwwii;
				 InsertOp = SF ? AArch64_UBFIZxxii : AArch64_UBFIZwwii;
				 break;
	}

	// Otherwise it's a boring insert or extract
	MCInst_addOperand(Inst, MCOperand_CreateImm(ImmR));
	MCInst_addOperand(Inst, MCOperand_CreateImm(ImmS));


	if (ImmS < ImmR)
		MCInst_setOpcode(Inst, InsertOp);
	else
		MCInst_setOpcode(Inst, ExtractOp);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMOVLaneInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	// This decoder exists to add the dummy Lane operand to the MCInst, which must
	// be 1 in assembly but has no other real manifestation.
	unsigned Rd = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned IsToVec = fieldFromInstruction(Insn, 16, 1);

	if (IsToVec) {
		DecodeFPR128RegisterClass(Inst, Rd, Address, Decoder);
		DecodeGPR64RegisterClass(Inst, Rn, Address, Decoder);
	} else {
		DecodeGPR64RegisterClass(Inst, Rd, Address, Decoder);
		DecodeFPR128RegisterClass(Inst, Rn, Address, Decoder);
	}

	// Add the lane
	MCInst_addOperand(Inst, MCOperand_CreateImm(1));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeLDSTPairInstruction(MCInst *Inst,
		unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	DecodeStatus Result = MCDisassembler_Success;
	unsigned Rt = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned Rt2 = fieldFromInstruction(Insn, 10, 5);
	unsigned SImm7 = fieldFromInstruction(Insn, 15, 7);
	unsigned L = fieldFromInstruction(Insn, 22, 1);
	unsigned V = fieldFromInstruction(Insn, 26, 1);
	unsigned Opc = fieldFromInstruction(Insn, 30, 2);

	// Not an official name, but it turns out that bit 23 distinguishes indexed
	// from non-indexed operations.
	unsigned Indexed = fieldFromInstruction(Insn, 23, 1);

	if (Indexed && L == 0) {
		// The MCInst for an indexed store has an out operand and 4 ins:
		//    Rn_wb, Rt, Rt2, Rn, Imm
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	}

	// You shouldn't load to the same register twice in an instruction...
	if (L && Rt == Rt2)
		Result = MCDisassembler_SoftFail;

	// ... or do any operation that writes-back to a transfer register. But note
	// that "stp xzr, xzr, [sp], #4" is fine because xzr and sp are different.
	if (Indexed && V == 0 && Rn != 31 && (Rt == Rn || Rt2 == Rn))
		Result = MCDisassembler_SoftFail;

	// Exactly how we decode the MCInst's registers depends on the Opc and V
	// fields of the instruction. These also obviously determine the size of the
	// operation so we can fill in that information while we're at it.
	if (V) {
		// The instruction operates on the FP/SIMD registers
		switch (Opc) {
			default: return MCDisassembler_Fail;
			case 0:
					 DecodeFPR32RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeFPR32RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
			case 1:
					 DecodeFPR64RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeFPR64RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
			case 2:
					 DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeFPR128RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
		}
	} else {
		switch (Opc) {
			default: return MCDisassembler_Fail;
			case 0:
					 DecodeGPR32RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeGPR32RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
			case 1:
					 //assert(L && "unexpected \"store signed\" attempt");
					 DecodeGPR64RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeGPR64RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
			case 2:
					 DecodeGPR64RegisterClass(Inst, Rt, Address, Decoder);
					 DecodeGPR64RegisterClass(Inst, Rt2, Address, Decoder);
					 break;
		}
	}

	if (Indexed && L == 1) {
		// The MCInst for an indexed load has 3 out operands and an 3 ins:
		//    Rt, Rt2, Rn_wb, Rt2, Rn, Imm
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	}


	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	MCInst_addOperand(Inst, MCOperand_CreateImm(SImm7));

	return Result;
}

static DecodeStatus DecodeLoadPairExclusiveInstruction(MCInst *Inst,
		uint32_t Val,
		uint64_t Address,
		void *Decoder)
{
	unsigned Rt = fieldFromInstruction(Val, 0, 5);
	unsigned Rn = fieldFromInstruction(Val, 5, 5);
	unsigned Rt2 = fieldFromInstruction(Val, 10, 5);
	unsigned MemSize = fieldFromInstruction(Val, 30, 2);

	DecodeStatus S = MCDisassembler_Success;
	if (Rt == Rt2) S = MCDisassembler_SoftFail;

	switch (MemSize) {
		case 2:
			if (!Check(&S, DecodeGPR32RegisterClass(Inst, Rt, Address, Decoder)))
				return MCDisassembler_Fail;
			if (!Check(&S, DecodeGPR32RegisterClass(Inst, Rt2, Address, Decoder)))
				return MCDisassembler_Fail;
			break;
		case 3:
			if (!Check(&S, DecodeGPR64RegisterClass(Inst, Rt, Address, Decoder)))
				return MCDisassembler_Fail;
			if (!Check(&S, DecodeGPR64RegisterClass(Inst, Rt2, Address, Decoder)))
				return MCDisassembler_Fail;
			break;
		default:
			break;	// never reach
	}

	if (!Check(&S, DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder)))
		return MCDisassembler_Fail;

	return S;
}

static DecodeStatus DecodeNamedImmOperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder, NamedImmMapper *N)
{
	bool ValidNamed;

	NamedImmMapper_toString(N, Val, &ValidNamed);
	if (ValidNamed || NamedImmMapper_validImm(N, Val)) {
		MCInst_addOperand(Inst, MCOperand_CreateImm(Val));
		return MCDisassembler_Success;
	}

	return MCDisassembler_Fail;
}

static DecodeStatus DecodeSysRegOperand(SysRegMapper *Mapper,
		MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	bool ValidNamed;
	char result[128];
	SysRegMapper_toString(Mapper, Val, &ValidNamed, result);

	MCInst_addOperand(Inst, MCOperand_CreateImm(Val));

	return ValidNamed ? MCDisassembler_Success : MCDisassembler_Fail;
}

static DecodeStatus DecodeMRSOperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	return DecodeSysRegOperand(&AArch64_MRSMapper, Inst, Val, Address, Decoder);
}

static DecodeStatus DecodeMSROperand(MCInst *Inst,
		unsigned Val,
		uint64_t Address,
		void *Decoder)
{
	return DecodeSysRegOperand(&AArch64_MSRMapper, Inst, Val, Address, Decoder);
}

static DecodeStatus DecodeSingleIndexedInstruction(MCInst *Inst,
		unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	unsigned Rt = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned Imm9 = fieldFromInstruction(Insn, 12, 9);

	unsigned Opc = fieldFromInstruction(Insn, 22, 2);
	unsigned V = fieldFromInstruction(Insn, 26, 1);
	unsigned Size = fieldFromInstruction(Insn, 30, 2);

	if (Opc == 0 || (V == 1 && Opc == 2)) {
		// It's a store, the MCInst gets: Rn_wb, Rt, Rn, Imm
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	}

	if (V == 0 && (Opc == 2 || Size == 3)) {
		DecodeGPR64RegisterClass(Inst, Rt, Address, Decoder);
	} else if (V == 0) {
		DecodeGPR32RegisterClass(Inst, Rt, Address, Decoder);
	} else if (V == 1 && (Opc & 2)) {
		DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder);
	} else {
		switch (Size) {
			case 0:
				DecodeFPR8RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 1:
				DecodeFPR16RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 2:
				DecodeFPR32RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 3:
				DecodeFPR64RegisterClass(Inst, Rt, Address, Decoder);
				break;
		}
	}

	if (Opc != 0 && (V != 1 || Opc != 2)) {
		// It's a load, the MCInst gets: Rt, Rn_wb, Rn, Imm
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	}

	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);

	MCInst_addOperand(Inst, MCOperand_CreateImm(Imm9));

	// N.b. The official documentation says undpredictable if Rt == Rn, but this
	// takes place at the architectural rather than encoding level:
	//
	// "STR xzr, [sp], #4" is perfectly valid.
	if (V == 0 && Rt == Rn && Rn != 31)
		return MCDisassembler_SoftFail;
	else
		return MCDisassembler_Success;
}

static DecodeStatus
DecodeNeonMovImmShiftOperand(MCInst *Inst, unsigned ShiftAmount,
		uint64_t Address, void *Decoder, A64SE_ShiftExtSpecifiers Ext, bool IsHalf)
{
	bool IsLSL = false;
	if (Ext == A64SE_LSL)
		IsLSL = true;
	else if (Ext != A64SE_MSL)
		return MCDisassembler_Fail;

	// MSL and LSLH accepts encoded shift amount 0 or 1.
	if ((!IsLSL || (IsLSL && IsHalf)) && ShiftAmount != 0 && ShiftAmount != 1)
		return MCDisassembler_Fail;

	// LSL  accepts encoded shift amount 0, 1, 2 or 3.
	if (IsLSL && ShiftAmount > 3)
		return MCDisassembler_Fail;

	MCInst_addOperand(Inst, MCOperand_CreateImm(ShiftAmount));
	return MCDisassembler_Success;
}

// Decode post-index vector load/store instructions.
// This is necessary as we need to decode Rm: if Rm == 0b11111, the last
// operand is an immediate equal the the length of vector list in bytes,
// or Rm is decoded to a GPR64noxzr register.
static DecodeStatus DecodeVLDSTPostInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	unsigned Rt = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned Rm = fieldFromInstruction(Insn, 16, 5);
	unsigned Opcode = fieldFromInstruction(Insn, 12, 4);
	unsigned IsLoad = fieldFromInstruction(Insn, 22, 1);
	// 0 for 64bit vector list, 1 for 128bit vector list
	unsigned Is128BitVec = fieldFromInstruction(Insn, 30, 1);

	unsigned NumVecs;
	switch (Opcode) {
		default:
			// llvm_unreachable("Invalid opcode for post-index load/store instructions");
		case 0: // ld4/st4
		case 2: // ld1/st1 with 4 vectors
			NumVecs = 4; break;
		case 4: // ld3/st3
		case 6: // ld1/st1 with 3 vectors
			NumVecs = 3; break;
		case 7: // ld1/st1 with 1 vector
			NumVecs = 1; break;
		case 8:  // ld2/st2
		case 10: // ld1/st1 with 2 vectors
			NumVecs = 2; break;
	}

	// Decode vector list of 1/2/3/4 vectors for load instructions.
	if (IsLoad) {
		switch (NumVecs) {
			case 1:
				Is128BitVec ? DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder)
					: DecodeFPR64RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 2:
				Is128BitVec ? DecodeQPairRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDPairRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 3:
				Is128BitVec ? DecodeQTripleRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDTripleRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 4:
				Is128BitVec ? DecodeQQuadRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDQuadRegisterClass(Inst, Rt, Address, Decoder);
				break;
		}
	}

	// Decode write back register, which is equal to Rn.
	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);

	if (Rm == 31) // If Rm is 0x11111, add the vector list length in byte
		MCInst_addOperand(Inst, MCOperand_CreateImm(NumVecs * (Is128BitVec ? 16 : 8)));
	else // Decode Rm
		DecodeGPR64noxzrRegisterClass(Inst, Rm, Address, Decoder);

	// Decode vector list of 1/2/3/4 vectors for load instructions.
	if (!IsLoad) {
		switch (NumVecs) {
			case 1:
				Is128BitVec ? DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder)
					: DecodeFPR64RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 2:
				Is128BitVec ? DecodeQPairRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDPairRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 3:
				Is128BitVec ? DecodeQTripleRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDTripleRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 4:
				Is128BitVec ? DecodeQQuadRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeDQuadRegisterClass(Inst, Rt, Address, Decoder);
				break;
		}
	}

	return MCDisassembler_Success;
}

// Decode post-index vector load/store lane instructions.
// This is necessary as we need to decode Rm: if Rm == 0b11111, the last
// operand is an immediate equal the the length of the changed bytes,
// or Rm is decoded to a GPR64noxzr register.
static DecodeStatus DecodeVLDSTLanePostInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	bool Is64bitVec = false;
	bool IsLoadDup = false;
	bool IsLoad = false;
	// The total number of bytes transferred.
	// TransferBytes = NumVecs * OneLaneBytes
	unsigned TransferBytes = 0;
	unsigned NumVecs = 0;
	unsigned Opc = MCInst_getOpcode(Inst);
	switch (Opc) {
		case AArch64_LD1R_WB_8B_fixed: case AArch64_LD1R_WB_8B_register:
		case AArch64_LD1R_WB_4H_fixed: case AArch64_LD1R_WB_4H_register:
		case AArch64_LD1R_WB_2S_fixed: case AArch64_LD1R_WB_2S_register:
		case AArch64_LD1R_WB_1D_fixed: case AArch64_LD1R_WB_1D_register:
			{
				switch (Opc) {
					case AArch64_LD1R_WB_8B_fixed: case AArch64_LD1R_WB_8B_register:
						TransferBytes = 1; break;
					case AArch64_LD1R_WB_4H_fixed: case AArch64_LD1R_WB_4H_register:
						TransferBytes = 2; break;
					case AArch64_LD1R_WB_2S_fixed: case AArch64_LD1R_WB_2S_register:
						TransferBytes = 4; break;
					case AArch64_LD1R_WB_1D_fixed: case AArch64_LD1R_WB_1D_register:
						TransferBytes = 8; break;
				}
				Is64bitVec = true;
				IsLoadDup = true;
				NumVecs = 1;
				break;
			}

		case AArch64_LD1R_WB_16B_fixed: case AArch64_LD1R_WB_16B_register:
		case AArch64_LD1R_WB_8H_fixed: case AArch64_LD1R_WB_8H_register:
		case AArch64_LD1R_WB_4S_fixed: case AArch64_LD1R_WB_4S_register:
		case AArch64_LD1R_WB_2D_fixed: case AArch64_LD1R_WB_2D_register:
			{
				switch (Opc) {
					case AArch64_LD1R_WB_16B_fixed: case AArch64_LD1R_WB_16B_register:
						TransferBytes = 1; break;
					case AArch64_LD1R_WB_8H_fixed: case AArch64_LD1R_WB_8H_register:
						TransferBytes = 2; break;
					case AArch64_LD1R_WB_4S_fixed: case AArch64_LD1R_WB_4S_register:
						TransferBytes = 4; break;
					case AArch64_LD1R_WB_2D_fixed: case AArch64_LD1R_WB_2D_register:
						TransferBytes = 8; break;
				}
				IsLoadDup = true;
				NumVecs = 1;
				break;
			}

		case AArch64_LD2R_WB_8B_fixed: case AArch64_LD2R_WB_8B_register:
		case AArch64_LD2R_WB_4H_fixed: case AArch64_LD2R_WB_4H_register:
		case AArch64_LD2R_WB_2S_fixed: case AArch64_LD2R_WB_2S_register:
		case AArch64_LD2R_WB_1D_fixed: case AArch64_LD2R_WB_1D_register:
			{
				switch (Opc) {
					case AArch64_LD2R_WB_8B_fixed: case AArch64_LD2R_WB_8B_register:
						TransferBytes = 2; break;
					case AArch64_LD2R_WB_4H_fixed: case AArch64_LD2R_WB_4H_register:
						TransferBytes = 4; break;
					case AArch64_LD2R_WB_2S_fixed: case AArch64_LD2R_WB_2S_register:
						TransferBytes = 8; break;
					case AArch64_LD2R_WB_1D_fixed: case AArch64_LD2R_WB_1D_register:
						TransferBytes = 16; break;
				}
				Is64bitVec = true;
				IsLoadDup = true;
				NumVecs = 2;
				break;
			}

		case AArch64_LD2R_WB_16B_fixed: case AArch64_LD2R_WB_16B_register:
		case AArch64_LD2R_WB_8H_fixed: case AArch64_LD2R_WB_8H_register:
		case AArch64_LD2R_WB_4S_fixed: case AArch64_LD2R_WB_4S_register:
		case AArch64_LD2R_WB_2D_fixed: case AArch64_LD2R_WB_2D_register:
			{
				switch (Opc) {
					case AArch64_LD2R_WB_16B_fixed: case AArch64_LD2R_WB_16B_register:
						TransferBytes = 2; break;
					case AArch64_LD2R_WB_8H_fixed: case AArch64_LD2R_WB_8H_register:
						TransferBytes = 4; break;
					case AArch64_LD2R_WB_4S_fixed: case AArch64_LD2R_WB_4S_register:
						TransferBytes = 8; break;
					case AArch64_LD2R_WB_2D_fixed: case AArch64_LD2R_WB_2D_register:
						TransferBytes = 16; break;
				}
				IsLoadDup = true;
				NumVecs = 2;
				break;
			}

		case AArch64_LD3R_WB_8B_fixed: case AArch64_LD3R_WB_8B_register:
		case AArch64_LD3R_WB_4H_fixed: case AArch64_LD3R_WB_4H_register:
		case AArch64_LD3R_WB_2S_fixed: case AArch64_LD3R_WB_2S_register:
		case AArch64_LD3R_WB_1D_fixed: case AArch64_LD3R_WB_1D_register:
			{
				switch (Opc) {
					case AArch64_LD3R_WB_8B_fixed: case AArch64_LD3R_WB_8B_register:
						TransferBytes = 3; break;
					case AArch64_LD3R_WB_4H_fixed: case AArch64_LD3R_WB_4H_register:
						TransferBytes = 6; break;
					case AArch64_LD3R_WB_2S_fixed: case AArch64_LD3R_WB_2S_register:
						TransferBytes = 12; break;
					case AArch64_LD3R_WB_1D_fixed: case AArch64_LD3R_WB_1D_register:
						TransferBytes = 24; break;
				}
				Is64bitVec = true;
				IsLoadDup = true;
				NumVecs = 3;
				break;
			}

		case AArch64_LD3R_WB_16B_fixed: case AArch64_LD3R_WB_16B_register:
		case AArch64_LD3R_WB_4S_fixed: case AArch64_LD3R_WB_8H_register:
		case AArch64_LD3R_WB_8H_fixed: case AArch64_LD3R_WB_4S_register:
		case AArch64_LD3R_WB_2D_fixed: case AArch64_LD3R_WB_2D_register:
			{
				switch (Opc) {
					case AArch64_LD3R_WB_16B_fixed: case AArch64_LD3R_WB_16B_register:
						TransferBytes = 3; break;
					case AArch64_LD3R_WB_8H_fixed: case AArch64_LD3R_WB_8H_register:
						TransferBytes = 6; break;
					case AArch64_LD3R_WB_4S_fixed: case AArch64_LD3R_WB_4S_register:
						TransferBytes = 12; break;
					case AArch64_LD3R_WB_2D_fixed: case AArch64_LD3R_WB_2D_register:
						TransferBytes = 24; break;
				}
				IsLoadDup = true;
				NumVecs = 3;
				break;
			}

		case AArch64_LD4R_WB_8B_fixed: case AArch64_LD4R_WB_8B_register:
		case AArch64_LD4R_WB_4H_fixed: case AArch64_LD4R_WB_4H_register:
		case AArch64_LD4R_WB_2S_fixed: case AArch64_LD4R_WB_2S_register:
		case AArch64_LD4R_WB_1D_fixed: case AArch64_LD4R_WB_1D_register:
			{
				switch (Opc) {
					case AArch64_LD4R_WB_8B_fixed: case AArch64_LD4R_WB_8B_register:
						TransferBytes = 4; break;
					case AArch64_LD4R_WB_4H_fixed: case AArch64_LD4R_WB_4H_register:
						TransferBytes = 8; break;
					case AArch64_LD4R_WB_2S_fixed: case AArch64_LD4R_WB_2S_register:
						TransferBytes = 16; break;
					case AArch64_LD4R_WB_1D_fixed: case AArch64_LD4R_WB_1D_register:
						TransferBytes = 32; break;
				}
				Is64bitVec = true;
				IsLoadDup = true;
				NumVecs = 4;
				break;
			}

		case AArch64_LD4R_WB_16B_fixed: case AArch64_LD4R_WB_16B_register:
		case AArch64_LD4R_WB_4S_fixed: case AArch64_LD4R_WB_8H_register:
		case AArch64_LD4R_WB_8H_fixed: case AArch64_LD4R_WB_4S_register:
		case AArch64_LD4R_WB_2D_fixed: case AArch64_LD4R_WB_2D_register:
			{
				switch (Opc) {
					case AArch64_LD4R_WB_16B_fixed: case AArch64_LD4R_WB_16B_register:
						TransferBytes = 4; break;
					case AArch64_LD4R_WB_8H_fixed: case AArch64_LD4R_WB_8H_register:
						TransferBytes = 8; break;
					case AArch64_LD4R_WB_4S_fixed: case AArch64_LD4R_WB_4S_register:
						TransferBytes = 16; break;
					case AArch64_LD4R_WB_2D_fixed: case AArch64_LD4R_WB_2D_register:
						TransferBytes = 32; break;
				}
				IsLoadDup = true;
				NumVecs = 4;
				break;
			}

		case AArch64_LD1LN_WB_B_fixed: case AArch64_LD1LN_WB_B_register:
		case AArch64_LD1LN_WB_H_fixed: case AArch64_LD1LN_WB_H_register:
		case AArch64_LD1LN_WB_S_fixed: case AArch64_LD1LN_WB_S_register:
		case AArch64_LD1LN_WB_D_fixed: case AArch64_LD1LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_LD1LN_WB_B_fixed: case AArch64_LD1LN_WB_B_register:
						TransferBytes = 1; break;
					case AArch64_LD1LN_WB_H_fixed: case AArch64_LD1LN_WB_H_register:
						TransferBytes = 2; break;
					case AArch64_LD1LN_WB_S_fixed: case AArch64_LD1LN_WB_S_register:
						TransferBytes = 4; break;
					case AArch64_LD1LN_WB_D_fixed: case AArch64_LD1LN_WB_D_register:
						TransferBytes = 8; break;
				}
				IsLoad = true;
				NumVecs = 1;
				break;
			}

		case AArch64_LD2LN_WB_B_fixed: case AArch64_LD2LN_WB_B_register:
		case AArch64_LD2LN_WB_H_fixed: case AArch64_LD2LN_WB_H_register:
		case AArch64_LD2LN_WB_S_fixed: case AArch64_LD2LN_WB_S_register:
		case AArch64_LD2LN_WB_D_fixed: case AArch64_LD2LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_LD2LN_WB_B_fixed: case AArch64_LD2LN_WB_B_register:
						TransferBytes = 2; break;
					case AArch64_LD2LN_WB_H_fixed: case AArch64_LD2LN_WB_H_register:
						TransferBytes = 4; break;
					case AArch64_LD2LN_WB_S_fixed: case AArch64_LD2LN_WB_S_register:
						TransferBytes = 8; break;
					case AArch64_LD2LN_WB_D_fixed: case AArch64_LD2LN_WB_D_register:
						TransferBytes = 16; break;
				}
				IsLoad = true;
				NumVecs = 2;
				break;
			}

		case AArch64_LD3LN_WB_B_fixed: case AArch64_LD3LN_WB_B_register:
		case AArch64_LD3LN_WB_H_fixed: case AArch64_LD3LN_WB_H_register:
		case AArch64_LD3LN_WB_S_fixed: case AArch64_LD3LN_WB_S_register:
		case AArch64_LD3LN_WB_D_fixed: case AArch64_LD3LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_LD3LN_WB_B_fixed: case AArch64_LD3LN_WB_B_register:
						TransferBytes = 3; break;
					case AArch64_LD3LN_WB_H_fixed: case AArch64_LD3LN_WB_H_register:
						TransferBytes = 6; break;
					case AArch64_LD3LN_WB_S_fixed: case AArch64_LD3LN_WB_S_register:
						TransferBytes = 12; break;
					case AArch64_LD3LN_WB_D_fixed: case AArch64_LD3LN_WB_D_register:
						TransferBytes = 24; break;
				}
				IsLoad = true;
				NumVecs = 3;
				break;
			}

		case AArch64_LD4LN_WB_B_fixed: case AArch64_LD4LN_WB_B_register:
		case AArch64_LD4LN_WB_H_fixed: case AArch64_LD4LN_WB_H_register:
		case AArch64_LD4LN_WB_S_fixed: case AArch64_LD4LN_WB_S_register:
		case AArch64_LD4LN_WB_D_fixed: case AArch64_LD4LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_LD4LN_WB_B_fixed: case AArch64_LD4LN_WB_B_register:
						TransferBytes = 4; break;
					case AArch64_LD4LN_WB_H_fixed: case AArch64_LD4LN_WB_H_register:
						TransferBytes = 8; break;
					case AArch64_LD4LN_WB_S_fixed: case AArch64_LD4LN_WB_S_register:
						TransferBytes = 16; break;
					case AArch64_LD4LN_WB_D_fixed: case AArch64_LD4LN_WB_D_register:
						TransferBytes = 32; break;
				}
				IsLoad = true;
				NumVecs = 4;
				break;
			}

		case AArch64_ST1LN_WB_B_fixed: case AArch64_ST1LN_WB_B_register:
		case AArch64_ST1LN_WB_H_fixed: case AArch64_ST1LN_WB_H_register:
		case AArch64_ST1LN_WB_S_fixed: case AArch64_ST1LN_WB_S_register:
		case AArch64_ST1LN_WB_D_fixed: case AArch64_ST1LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_ST1LN_WB_B_fixed: case AArch64_ST1LN_WB_B_register:
						TransferBytes = 1; break;
					case AArch64_ST1LN_WB_H_fixed: case AArch64_ST1LN_WB_H_register:
						TransferBytes = 2; break;
					case AArch64_ST1LN_WB_S_fixed: case AArch64_ST1LN_WB_S_register:
						TransferBytes = 4; break;
					case AArch64_ST1LN_WB_D_fixed: case AArch64_ST1LN_WB_D_register:
						TransferBytes = 8; break;
				}
				NumVecs = 1;
				break;
			}

		case AArch64_ST2LN_WB_B_fixed: case AArch64_ST2LN_WB_B_register:
		case AArch64_ST2LN_WB_H_fixed: case AArch64_ST2LN_WB_H_register:
		case AArch64_ST2LN_WB_S_fixed: case AArch64_ST2LN_WB_S_register:
		case AArch64_ST2LN_WB_D_fixed: case AArch64_ST2LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_ST2LN_WB_B_fixed: case AArch64_ST2LN_WB_B_register:
						TransferBytes = 2; break;
					case AArch64_ST2LN_WB_H_fixed: case AArch64_ST2LN_WB_H_register:
						TransferBytes = 4; break;
					case AArch64_ST2LN_WB_S_fixed: case AArch64_ST2LN_WB_S_register:
						TransferBytes = 8; break;
					case AArch64_ST2LN_WB_D_fixed: case AArch64_ST2LN_WB_D_register:
						TransferBytes = 16; break;
				}
				NumVecs = 2;
				break;
			}

		case AArch64_ST3LN_WB_B_fixed: case AArch64_ST3LN_WB_B_register:
		case AArch64_ST3LN_WB_H_fixed: case AArch64_ST3LN_WB_H_register:
		case AArch64_ST3LN_WB_S_fixed: case AArch64_ST3LN_WB_S_register:
		case AArch64_ST3LN_WB_D_fixed: case AArch64_ST3LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_ST3LN_WB_B_fixed: case AArch64_ST3LN_WB_B_register:
						TransferBytes = 3; break;
					case AArch64_ST3LN_WB_H_fixed: case AArch64_ST3LN_WB_H_register:
						TransferBytes = 6; break;
					case AArch64_ST3LN_WB_S_fixed: case AArch64_ST3LN_WB_S_register:
						TransferBytes = 12; break;
					case AArch64_ST3LN_WB_D_fixed: case AArch64_ST3LN_WB_D_register:
						TransferBytes = 24; break;
				}
				NumVecs = 3;
				break;
			}

		case AArch64_ST4LN_WB_B_fixed: case AArch64_ST4LN_WB_B_register:
		case AArch64_ST4LN_WB_H_fixed: case AArch64_ST4LN_WB_H_register:
		case AArch64_ST4LN_WB_S_fixed: case AArch64_ST4LN_WB_S_register:
		case AArch64_ST4LN_WB_D_fixed: case AArch64_ST4LN_WB_D_register:
			{
				switch (Opc) {
					case AArch64_ST4LN_WB_B_fixed: case AArch64_ST4LN_WB_B_register:
						TransferBytes = 4; break;
					case AArch64_ST4LN_WB_H_fixed: case AArch64_ST4LN_WB_H_register:
						TransferBytes = 8; break;
					case AArch64_ST4LN_WB_S_fixed: case AArch64_ST4LN_WB_S_register:
						TransferBytes = 16; break;
					case AArch64_ST4LN_WB_D_fixed: case AArch64_ST4LN_WB_D_register:
						TransferBytes = 32; break;
				}
				NumVecs = 4;
				break;
			}

		default:
			return MCDisassembler_Fail;
	} // End of switch (Opc)

	unsigned Rt = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned Rm = fieldFromInstruction(Insn, 16, 5);

	// Decode post-index of load duplicate lane
	if (IsLoadDup) {
		switch (NumVecs) {
			case 1:
				Is64bitVec ? DecodeFPR64RegisterClass(Inst, Rt, Address, Decoder)
					: DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 2:
				Is64bitVec ? DecodeDPairRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeQPairRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 3:
				Is64bitVec ? DecodeDTripleRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeQTripleRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 4:
				Is64bitVec ? DecodeDQuadRegisterClass(Inst, Rt, Address, Decoder)
					: DecodeQQuadRegisterClass(Inst, Rt, Address, Decoder);
		}

		// Decode write back register, which is equal to Rn.
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
		DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);

		if (Rm == 31) // If Rm is 0x11111, add the number of transferred bytes
			MCInst_addOperand(Inst, MCOperand_CreateImm(TransferBytes));
		else // Decode Rm
			DecodeGPR64noxzrRegisterClass(Inst, Rm, Address, Decoder);

		return MCDisassembler_Success;
	}

	// Decode post-index of load/store lane
	// Loads have a vector list as output.
	if (IsLoad) {
		switch (NumVecs) {
			case 1:
				DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 2:
				DecodeQPairRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 3:
				DecodeQTripleRegisterClass(Inst, Rt, Address, Decoder);
				break;
			case 4:
				DecodeQQuadRegisterClass(Inst, Rt, Address, Decoder);
		}
	}

	// Decode write back register, which is equal to Rn.
	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);
	DecodeGPR64xspRegisterClass(Inst, Rn, Address, Decoder);

	if (Rm == 31) // If Rm is 0x11111, add the number of transferred bytes
		MCInst_addOperand(Inst, MCOperand_CreateImm(TransferBytes));
	else // Decode Rm
		DecodeGPR64noxzrRegisterClass(Inst, Rm, Address, Decoder);

	// Decode the source vector list.
	switch (NumVecs) {
		case 1:
			DecodeFPR128RegisterClass(Inst, Rt, Address, Decoder);
			break;
		case 2:
			DecodeQPairRegisterClass(Inst, Rt, Address, Decoder);
			break;
		case 3:
			DecodeQTripleRegisterClass(Inst, Rt, Address, Decoder);
			break;
		case 4:
			DecodeQQuadRegisterClass(Inst, Rt, Address, Decoder);
	}

	// Decode lane
	unsigned Q = fieldFromInstruction(Insn, 30, 1);
	unsigned S = fieldFromInstruction(Insn, 10, 3);
	unsigned lane = 0;
	// Calculate the number of lanes by number of vectors and transfered bytes.
	// NumLanes = 16 bytes / bytes of each lane
	unsigned NumLanes = 16 / (TransferBytes / NumVecs);
	switch (NumLanes) {
		case 16: // A vector has 16 lanes, each lane is 1 bytes.
			lane = (Q << 3) | S;
			break;
		case 8:
			lane = (Q << 2) | (S >> 1);
			break;
		case 4:
			lane = (Q << 1) | (S >> 2);
			break;
		case 2:
			lane = Q;
			break;
	}
	MCInst_addOperand(Inst, MCOperand_CreateImm(lane));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSHLLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address,
		void *Decoder)
{
	unsigned Rd = fieldFromInstruction(Insn, 0, 5);
	unsigned Rn = fieldFromInstruction(Insn, 5, 5);
	unsigned size = fieldFromInstruction(Insn, 22, 2);
	unsigned Q = fieldFromInstruction(Insn, 30, 1);

	DecodeFPR128RegisterClass(Inst, Rd, Address, Decoder);

	if (Q)
		DecodeFPR128RegisterClass(Inst, Rn, Address, Decoder);
	else
		DecodeFPR64RegisterClass(Inst, Rn, Address, Decoder);

	switch (size) {
		case 0:
			MCInst_addOperand(Inst, MCOperand_CreateImm(8));
			break;
		case 1:
			MCInst_addOperand(Inst, MCOperand_CreateImm(16));
			break;
		case 2:
			MCInst_addOperand(Inst, MCOperand_CreateImm(32));
			break;
		default :
			return MCDisassembler_Fail;
	}
	return MCDisassembler_Success;
}

