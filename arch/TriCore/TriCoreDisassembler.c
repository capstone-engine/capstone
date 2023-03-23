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
	const MCRegisterClass *rc = MCRegisterInfo_getRegClass(MRI, RC);
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

static DecodeStatus DecodeSLRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSLROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSRRSInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSBCInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSBRNInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSSRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSSROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeSYSInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRRR2Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRRR1Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeBITInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRR1Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRCRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRRRWInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRCRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRRRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeBRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeBRCInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeABSBInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeRCRWInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);
static DecodeStatus DecodeBRNInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder);

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
		case TriCore_ADD_src:
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
		case TriCore_MOV_AA_srr:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_ADD_srr:
		case TriCore_MUL_srr:
		case TriCore_AND_srr:
		case TriCore_OR_srr:
		case TriCore_XOR_srr:
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
		case TriCore_MOV_AA_srr:
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
		case TriCore_LD_A_abs:
		case TriCore_ST_A_abs:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_D_abs:
		case TriCore_ST_D_abs:
			status = DecodeExtRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_DA_abs:
		case TriCore_ST_DA_abs:
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
		case TriCore_LD_A_bo_bso:
		case TriCore_LD_A_bo_pre:
		case TriCore_LD_A_bo_pos:
		case TriCore_LD_A_bo_c:
		case TriCore_LD_A_bo_r:
		case TriCore_ST_A_bo_bso:
		case TriCore_ST_A_bo_pre:
		case TriCore_ST_A_bo_pos:
		case TriCore_ST_A_bo_c:
		case TriCore_ST_A_bo_r:
			status = DecodeAddrRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_D_bo_bso:
		case TriCore_LD_D_bo_pre:
		case TriCore_LD_D_bo_pos:
		case TriCore_LD_D_bo_c:
		case TriCore_LD_D_bo_r:
		case TriCore_ST_D_bo_bso:
		case TriCore_ST_D_bo_pre:
		case TriCore_ST_D_bo_pos:
		case TriCore_ST_D_bo_c:
		case TriCore_ST_D_bo_r:
			status = DecodeExtRegsRegisterClass(Inst, s1_d, Address, Decoder);
			break;
		case TriCore_LD_DA_bo_bso:
		case TriCore_LD_DA_bo_pre:
		case TriCore_LD_DA_bo_pos:
		case TriCore_LD_DA_bo_c:
		case TriCore_LD_DA_bo_r:
		case TriCore_ST_DA_bo_bso:
		case TriCore_ST_DA_bo_pre:
		case TriCore_ST_DA_bo_pos:
		case TriCore_ST_DA_bo_c:
		case TriCore_ST_DA_bo_r:
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
		case TriCore_LD_B_bo_c:
		case TriCore_LD_BU_bo_c:
		case TriCore_LD_H_bo_c:
		case TriCore_LD_HU_bo_c:
		case TriCore_LD_W_bo_c:
		case TriCore_LD_D_bo_c:
		case TriCore_LD_A_bo_c:
		case TriCore_LD_DA_bo_c:
		case TriCore_ST_B_bo_c:
		case TriCore_ST_H_bo_c:
		case TriCore_ST_W_bo_c:
		case TriCore_ST_D_bo_c:
		case TriCore_ST_Q_bo_c:
		case TriCore_ST_A_bo_c:
		case TriCore_ST_DA_bo_c:
		case TriCore_LD_B_bo_r:
		case TriCore_LD_BU_bo_r:
		case TriCore_LD_H_bo_r:
		case TriCore_LD_HU_bo_r:
		case TriCore_LD_W_bo_r:
		case TriCore_LD_D_bo_r:
		case TriCore_LD_A_bo_r:
		case TriCore_LD_DA_bo_r:
		case TriCore_ST_B_bo_r:
		case TriCore_ST_H_bo_r:
		case TriCore_ST_W_bo_r:
		case TriCore_ST_D_bo_r:
		case TriCore_ST_Q_bo_r:
		case TriCore_ST_A_bo_r:
		case TriCore_ST_DA_bo_r:
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
		case TriCore_LD_A_bol:
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
		case TriCore_AND_EQ_rc:
		case TriCore_AND_NE_rc:
		case TriCore_AND_LT_rc:
		case TriCore_AND_LT_U_rc:
		case TriCore_AND_GE_rc:
		case TriCore_AND_GE_U_rc:
		case TriCore_OR_EQ_rc:
		case TriCore_OR_NE_rc:
		case TriCore_OR_LT_rc:
		case TriCore_OR_LT_U_rc:
		case TriCore_OR_GE_rc:
		case TriCore_OR_GE_U_rc:
		case TriCore_XOR_EQ_rc:
		case TriCore_XOR_NE_rc:
		case TriCore_XOR_LT_rc:
		case TriCore_XOR_LT_U_rc:
		case TriCore_XOR_GE_rc:
		case TriCore_XOR_GE_U_rc:
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
		case TriCore_MOV_rlcDc:
		case TriCore_MOV_rlcEc:
		case TriCore_MOV_U_rlc:
		case TriCore_MOV_H_rlc:
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
		case TriCore_ADD_A_rr:
		case TriCore_SUB_A_rr:
		case TriCore_MOV_A_rr:
		case TriCore_MOV_AA_rr:
			status = DecodeAddrRegsRegisterClass(Inst, d, Address, Decoder);
			break;
		case TriCore_AND_EQ_rr:
		case TriCore_AND_NE_rr:
		case TriCore_AND_LT_rr:
		case TriCore_AND_LT_U_rr:
		case TriCore_AND_GE_rr:
		case TriCore_AND_GE_U_rr:
		case TriCore_OR_EQ_rr:
		case TriCore_OR_NE_rr:
		case TriCore_OR_LT_rr:
		case TriCore_OR_LT_U_rr:
		case TriCore_OR_GE_rr:
		case TriCore_OR_GE_U_rr:
		case TriCore_XOR_EQ_rr:
		case TriCore_XOR_NE_rr:
		case TriCore_XOR_LT_rr:
		case TriCore_XOR_LT_U_rr:
		case TriCore_XOR_GE_rr:
		case TriCore_XOR_GE_U_rr:
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
		case TriCore_ADD_A_rr:
		case TriCore_SUB_A_rr:
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
		case TriCore_ADD_A_rr:
		case TriCore_SUB_A_rr:
		case TriCore_MOV_D_rr:
		case TriCore_MOV_AA_rr:
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

static DecodeStatus DecodeSLRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSLROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSRRSInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSBCInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSBRNInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSSRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSSROInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeSYSInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRRR2Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRRR1Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeBITInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRR1Instruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRCRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRRRWInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRCRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRRRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeBRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeBRCInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRRRInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeABSBInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeRCRWInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
}
static DecodeStatus DecodeBRNInstruction(MCInst *Inst, unsigned Insn, uint64_t Address, void *Decoder){
	// TODO: DecodeBRNInstruction
	return MCDisassembler_Fail;
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
	Result = decodeInstruction_2(DecoderTable16, MI, insn16, address);
	if (Result != MCDisassembler_Fail) {
		*size = 2;
		return true;
	}

	if (!readInstruction32(code, code_len, &insn32)) {
		return false;
	}

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_4(DecoderTable32, MI, insn32, address);
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
