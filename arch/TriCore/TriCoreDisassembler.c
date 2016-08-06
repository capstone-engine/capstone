//===------ TriCoreDisassembler.cpp - Disassembler for TriCore --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h>	// DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../MathExtras.h"

static uint64_t getFeatureBits(int mode)
{
	// support everything
	return (uint64_t)-1;
}

static bool readInstruction16(const uint8_t *code, size_t code_len, uint16_t *insn)
{
	if (code_len < 2)
		// insufficient data
		return false;

	// Encoded as a little-endian 16-bit word in the stream.
	*insn = (code[0] <<  0) | (code[1] <<  8);
	return true;
}

static bool readInstruction32(const uint8_t *code, size_t code_len, uint32_t *insn)
{
	if (code_len < 4)
		// insufficient data
		return false;

	// Encoded as a little-endian 32-bit word in the stream.
	*insn = (code[0] << 0) | (code[1] << 8) | (code[2] << 16) | (code[3] << 24);
	return true;
}

static unsigned getReg(MCRegisterInfo *MRI, unsigned RC, unsigned RegNo)
{
	MCRegisterClass *rc = MCRegisterInfo_getRegClass(MRI, RC);
	return rc->RegsBegin[RegNo];
}

static DecodeStatus DecodeDataRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeAddrRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeExtRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSBRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSRCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSRRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeBInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeBOInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeBOLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRCPWInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRCLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRR2Instruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeRRPWInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder);

#include "TriCoreGenDisassemblerTables.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "TriCoreGenRegisterInfo.inc"

static DecodeStatus DecodeDataRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	unsigned Reg;

	if (RegNo > 15)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_DataRegsRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeAddrRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	unsigned Reg;

	if (RegNo < 16 || RegNo > 31)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_AddrRegsRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeExtRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	unsigned Reg;

	if (RegNo < 32 || RegNo > 39)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_ExtRegsRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeOperandRegister(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	// Decode Data Register
	DecodeStatus status = DecodeDataRegsRegisterClass(Inst, RegNo, Address,
							Decoder);

	if (status == MCDisassembler_Success)
		return status;

	// Decode Address Register
	status = DecodeAddrRegsRegisterClass(Inst, RegNo, Address, Decoder);
	if (status == MCDisassembler_Success)
		return status;

	// Decode Extended 64-bit Register
	status = DecodeExtRegsRegisterClass(Inst, RegNo, Address, Decoder);
	return status;
}


#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

static DecodeStatus DecodeSBRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	unsigned const8 = fieldFromInstruction_4(Insn, 8, 8);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode const8.
	MCOperand_CreateImm0(Inst, const8);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode s1/d.
	status = DecodeOperandRegister(Inst, s1_d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

	// Decode s1/d.
	status = DecodeOperandRegister(Inst, s1_d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1/d.
	status = DecodeOperandRegister(Inst, s1_d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	unsigned disp24_0 = fieldFromInstruction_4(Insn, 16, 16);
	unsigned disp24_1 = fieldFromInstruction_4(Insn, 8, 8);
	unsigned disp24 = (disp24_0 << 0) | (disp24_1 << 16);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode disp24.
	MCOperand_CreateImm0(Inst, disp24);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBOInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned off10_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off10_1 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off10 = (off10_0 << 0) | (off10_1 << 6);

	unsigned s2 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 22, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode off10.
	MCOperand_CreateImm0(Inst, off10);

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1_d.
	status = DecodeOperandRegister(Inst, s1_d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBOLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned off16_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off16_1 = fieldFromInstruction_4(Insn, 22, 6);
	unsigned off16_2 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off16 = (off16_0 << 0) | (off16_1 << 6) | (off16_2 << 6);

	unsigned s2 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 22, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode off16.
	MCOperand_CreateImm0(Inst, off16);

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1_d.
	status = DecodeOperandRegister(Inst, s1_d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned const9 = fieldFromInstruction_4(Insn, 12, 9);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
	return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const9.
	MCOperand_CreateImm0(Inst, const9);

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCPWInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned pos = fieldFromInstruction_4(Insn, 23, 5);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode pos.
	MCOperand_CreateImm0(Inst, pos);

	// Decode width.
	MCOperand_CreateImm0(Inst, width);

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCLInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned const16 = fieldFromInstruction_4(Insn, 12, 16);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const16.
	MCOperand_CreateImm0(Inst, const16);

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned n = fieldFromInstruction_4(Insn, 16, 2);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode n.
	MCOperand_CreateImm0(Inst, n);

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRR2Instruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRPWInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned pos = fieldFromInstruction_4(Insn, 23, 5);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode d.
	status = DecodeOperandRegister(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode pos.
	MCOperand_CreateImm0(Inst, pos);

	// Decode width.
	MCOperand_CreateImm0(Inst, width);

	// Decode s2.
	status = DecodeOperandRegister(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeOperandRegister(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

#define GET_SUBTARGETINFO_ENUM
#include "TriCoreGenInstrInfo.inc"
bool TriCore_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *MI,
		uint16_t *size, uint64_t address, void *info)
{
	uint16_t insn16;
	uint32_t insn32;
	DecodeStatus Result;

	if (!readInstruction16(code, code_len, &insn16)) {
		return false;
	}

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, sizeof(cs_detail));
	}

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_2(DecoderTable16, MI, insn16, address, info, 0);
	if (Result != MCDisassembler_Fail) {
		*size = 2;
		return true;
	}

	if (!readInstruction32(code, code_len, &insn32)) {
		return false;
	}

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_4(DecoderTable32, MI, insn32, address, info, 0);
	if (Result != MCDisassembler_Fail) {
		*size = 4;
		return true;
	}

	return false;
}

void TriCore_init(MCRegisterInfo *MRI)
{
	/*
	InitMCRegisterInfo(TriCoreRegDesc, 45, RA, PC,
			TriCoreMCRegisterClasses, 4,
			TriCoreRegUnitRoots,
			16,
			TriCoreRegDiffLists,
			TriCoreRegStrings,
			TriCoreSubRegIdxLists,
			1,
			TriCoreSubRegIdxRanges,
			TriCoreRegEncodingTable);
	*/


	MCRegisterInfo_InitMCRegisterInfo(MRI, TriCoreRegDesc, 45,
			0, 0,
			TriCoreMCRegisterClasses, 4,
			0, 0,
			TriCoreRegDiffLists,
			0,
			TriCoreSubRegIdxLists, 1,
			0);
}

#endif
