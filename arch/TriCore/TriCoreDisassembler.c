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

static DecodeStatus DecodePairAddrRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder);

static DecodeStatus DecodeSBInstruction(MCInst *Inst, unsigned Insn,
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

static DecodeStatus DecodeABSInstruction(MCInst *Inst, unsigned Insn,
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

static DecodeStatus DecodeRLCInstruction(MCInst *Inst, unsigned Insn,
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

	if (RegNo > 15)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_AddrRegsRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeExtRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	unsigned Reg;
	unsigned RegHalfNo = RegNo / 2;

	if (RegHalfNo > 15)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_ExtRegsRegClassID, RegHalfNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

static DecodeStatus DecodePairAddrRegsRegisterClass(MCInst *Inst, unsigned RegNo,
		uint64_t Address, void *Decoder)
{
	unsigned Reg;
	unsigned RegHalfNo = RegNo / 2;

	if (RegHalfNo > 15)
		return MCDisassembler_Fail;

	Reg = getReg(Decoder, TriCore_PairAddrRegsRegClassID, RegHalfNo);
	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

static DecodeStatus DecodeSBInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	unsigned disp8 = fieldFromInstruction_4(Insn, 8, 8);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode disp8.
	MCOperand_CreateImm0(Inst, disp8);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSBRInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{
	DecodeStatus status;
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned disp4 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	// Decode s2.
	status = DecodeDataRegsRegisterClass(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode disp4.
	MCOperand_CreateImm0(Inst, disp4);

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
	status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
	if (status == MCDisassembler_Success)
		status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);

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

	// Decode s1/d.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_ADDsrc:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			if (status == MCDisassembler_Success)
				status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

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

	// Decode s1/d.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_MOV_AAsrr:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_ADDsrr:
		case TriCore_MULsrr:
		case TriCore_ANDsrr:
		case TriCore_ORsrr:
		case TriCore_XORsrr:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			if (status == MCDisassembler_Success)
				status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;


	// Decode s2.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_MOV_AAsrr:
			status = DecodeAddrRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeABSInstruction(MCInst *Inst, unsigned Insn,
		uint64_t Address, void *Decoder)
{

	DecodeStatus status;
	unsigned off18_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off18_1 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off18_2 = fieldFromInstruction_4(Insn, 22, 4);
	unsigned off18_3 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned off18 = (off18_0 << 0) | (off18_1 << 6) |
		(off18_2 << 10) | (off18_3 << 14);

	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if(!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode s1_d.
	switch (MCInst_getOpcode(Inst)) {
		case TriCore_LD_Aabs:
		case TriCore_ST_Aabs:    
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_Dabs:
		case TriCore_ST_Dabs:    
			status = DecodeExtRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_DAabs:
		case TriCore_ST_DAabs:    
			status = DecodePairAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode off18.
	MCOperand_CreateImm0(Inst, off18);

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

	// Decode s1_d.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_LD_Abo:
		case TriCore_LD_Apreincbo:
		case TriCore_LD_Apostincbo:
		case TriCore_LD_Acircbo:
		case TriCore_LD_Abitrevbo:
		case TriCore_ST_Abo:
		case TriCore_ST_Apreincbo:
		case TriCore_ST_Apostincbo:
		case TriCore_ST_Acircbo:
		case TriCore_ST_Abitrevbo:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_Dbo:
		case TriCore_LD_Dpreincbo:
		case TriCore_LD_Dpostincbo:
		case TriCore_LD_Dcircbo:
		case TriCore_LD_Dbitrevbo:
		case TriCore_ST_Dbo:
		case TriCore_ST_Dpreincbo:
		case TriCore_ST_Dpostincbo:
		case TriCore_ST_Dcircbo:
		case TriCore_ST_Dbitrevbo:
			status = DecodeExtRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_DAbo:
		case TriCore_LD_DApreincbo:
		case TriCore_LD_DApostincbo:
		case TriCore_LD_DAcircbo:
		case TriCore_LD_DAbitrevbo:
		case TriCore_ST_DAbo:
		case TriCore_ST_DApreincbo:
		case TriCore_ST_DApostincbo:
		case TriCore_ST_DAcircbo:    
		case TriCore_ST_DAbitrevbo:
			status = DecodePairAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_LD_Bcircbo:
		case TriCore_LD_BUcircbo:
		case TriCore_LD_Hcircbo:
		case TriCore_LD_HUcircbo:
		case TriCore_LD_Wcircbo:
		case TriCore_LD_Dcircbo:
		case TriCore_LD_Acircbo:
		case TriCore_LD_DAcircbo:
		case TriCore_ST_Bcircbo:
		case TriCore_ST_Hcircbo:
		case TriCore_ST_Wcircbo:
		case TriCore_ST_Dcircbo:
		case TriCore_ST_Qcircbo:
		case TriCore_ST_Acircbo:
		case TriCore_ST_DAcircbo:
		case TriCore_LD_Bbitrevbo:
		case TriCore_LD_BUbitrevbo:
		case TriCore_LD_Hbitrevbo:
		case TriCore_LD_HUbitrevbo:
		case TriCore_LD_Wbitrevbo:
		case TriCore_LD_Dbitrevbo:
		case TriCore_LD_Abitrevbo:
		case TriCore_LD_DAbitrevbo:
		case TriCore_ST_Bbitrevbo:
		case TriCore_ST_Hbitrevbo:
		case TriCore_ST_Wbitrevbo:
		case TriCore_ST_Dbitrevbo:
		case TriCore_ST_Qbitrevbo:
		case TriCore_ST_Abitrevbo:
		case TriCore_ST_DAbitrevbo:
			status = DecodePairAddrRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
		default:
			status = DecodeAddrRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode off10.
	MCOperand_CreateImm0(Inst, off10);

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

	// Decode s1_d.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_LD_Abol:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeAddrRegsRegisterClass(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode off16.
	MCOperand_CreateImm0(Inst, off16);

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
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_AND_EQrc:
		case TriCore_AND_NErc:
		case TriCore_AND_LTrc:
		case TriCore_AND_LT_Urc:
		case TriCore_AND_GErc:
		case TriCore_AND_GE_Urc:
		case TriCore_OR_EQrc:
		case TriCore_OR_NErc:
		case TriCore_OR_LTrc:
		case TriCore_OR_LT_Urc:
		case TriCore_OR_GErc:
		case TriCore_OR_GE_Urc:
		case TriCore_XOR_EQrc:
		case TriCore_XOR_NErc:
		case TriCore_XOR_LTrc:
		case TriCore_XOR_LT_Urc:
		case TriCore_XOR_GErc:
		case TriCore_XOR_GE_Urc:
			status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			if (status == MCDisassembler_Success)
				status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const9.
	MCOperand_CreateImm0(Inst, const9);

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
	status = DecodeExtRegsRegisterClass(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

	// Decode pos.
	MCOperand_CreateImm0(Inst, pos);

	// Decode width.
	MCOperand_CreateImm0(Inst, width);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRLCInstruction(MCInst *Inst, unsigned Insn,
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
	status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	switch(MCInst_getOpcode(Inst)) {
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
			break;
		case TriCore_MOVrlc:
		case TriCore_MOV_Urlc:
		case TriCore_MOVHrlc:
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode const16.
	MCOperand_CreateImm0(Inst, const16);

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
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_ADD_Arr:
		case TriCore_SUB_Arr:
		case TriCore_MOV_Arr:
		case TriCore_MOV_AArr:
			status = DecodeAddrRegsRegisterClass(Inst, d, Address, Decoder);
			break;
		case TriCore_AND_EQrr:
		case TriCore_AND_NErr:
		case TriCore_AND_LTrr:
		case TriCore_AND_LT_Urr:
		case TriCore_AND_GErr:
		case TriCore_AND_GE_Urr:
		case TriCore_OR_EQrr:
		case TriCore_OR_NErr:
		case TriCore_OR_LTrr:
		case TriCore_OR_LT_Urr:
		case TriCore_OR_GErr:
		case TriCore_OR_GE_Urr:
		case TriCore_XOR_EQrr:
		case TriCore_XOR_NErr:
		case TriCore_XOR_LTrr:
		case TriCore_XOR_LT_Urr:
		case TriCore_XOR_GErr:
		case TriCore_XOR_GE_Urr:
			status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			if (status == MCDisassembler_Success)
				status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_ADD_Arr:
		case TriCore_SUB_Arr:
			status = DecodeAddrRegsRegisterClass(Inst, s1, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	switch(MCInst_getOpcode(Inst)) {
		case TriCore_ADD_Arr:
		case TriCore_SUB_Arr:
		case TriCore_MOV_Drr:
		case TriCore_MOV_AArr:
			status = DecodeAddrRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
		default:
			status = DecodeDataRegsRegisterClass(Inst, s2, Address, Decoder);
			break;
	}
	if (status != MCDisassembler_Success)
		return status;

	// Decode n.
	MCOperand_CreateImm0(Inst, n);

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
	status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeDataRegsRegisterClass(Inst, s2, Address, Decoder);
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
	status = DecodeDataRegsRegisterClass(Inst, d, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeDataRegsRegisterClass(Inst, s1, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeDataRegsRegisterClass(Inst, s2, Address, Decoder);
	if (status != MCDisassembler_Success)
		return status;

	// Decode pos.
	MCOperand_CreateImm0(Inst, pos);

	// Decode width.
	MCOperand_CreateImm0(Inst, width);

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


	MCRegisterInfo_InitMCRegisterInfo(MRI, TriCoreRegDesc, 53,
			0, 0,
			TriCoreMCRegisterClasses, 5,
			0, 0,
			TriCoreRegDiffLists,
			0,
			TriCoreSubRegIdxLists, 1,
			0);
}

#endif
