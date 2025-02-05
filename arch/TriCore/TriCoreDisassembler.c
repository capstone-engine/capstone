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

#include <stdio.h> // DEBUG
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

#include "TriCoreDisassembler.h"
#include "TriCoreMapping.h"
#include "TriCoreLinkage.h"

static unsigned getReg(const MCRegisterInfo *MRI, unsigned RC, unsigned RegNo)
{
	const MCRegisterClass *rc = MCRegisterInfo_getRegClass(MRI, RC);
	return MCRegisterClass_getRegister(rc, RegNo);
}

#define tryDecodeReg(i, x) \
	status = DecodeRegisterClass(Inst, (x), &desc->OpInfo[(i)]); \
	if (status != MCDisassembler_Success) \
		return status;

#define decodeImm(x) MCOperand_CreateImm0(Inst, (x));

static DecodeStatus DecodeSBInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSBRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSCInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSRInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSRCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeABSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBInstruction(MCInst *Inst, unsigned Insn,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBOInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBOLInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRCInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRCPWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeRLCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRRInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRR2Instruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRRPWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeSLRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSLROInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeSROInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSRRSInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeSBCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSBRNInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeSSRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSSROInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeSYSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRRR2Instruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeRRR1Instruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeBITInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRR1Instruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRCRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRRRWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeRCRRInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeRRRRInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeBRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBRCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeABSBInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeRCRWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeBRNInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder);

#define GET_SUBTARGETINFO_ENUM

#include "TriCoreGenSubtargetInfo.inc"

bool TriCore_getFeatureBits(unsigned int mode, unsigned int feature)
{
	switch (mode) {
	case CS_MODE_TRICORE_110: {
		return feature == TriCore_HasV110Ops;
	}
	case CS_MODE_TRICORE_120: {
		return feature == TriCore_HasV120Ops;
	}
	case CS_MODE_TRICORE_130: {
		return feature == TriCore_HasV130Ops;
	}
	case CS_MODE_TRICORE_131: {
		return feature == TriCore_HasV131Ops;
	}
	case CS_MODE_TRICORE_160: {
		return feature == TriCore_HasV160Ops;
	}
	case CS_MODE_TRICORE_161: {
		return feature == TriCore_HasV161Ops;
	}
	case CS_MODE_TRICORE_162: {
		return feature == TriCore_HasV162Ops;
	}
	case CS_MODE_TRICORE_180: {
		return feature == TriCore_HasV180Ops;
	}
	default:
		return false;
	}
}

#include "TriCoreGenDisassemblerTables.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC

#include "TriCoreGenRegisterInfo.inc"

static DecodeStatus DecodeRegisterClass(MCInst *Inst, unsigned RegNo,
					const MCOperandInfo *MCOI)
{
	unsigned Reg;
	unsigned RegHalfNo = RegNo / 2;

	if (!MCOI || MCOI->OperandType != MCOI_OPERAND_REGISTER) {
		return MCDisassembler_Fail;
	}

	if (RegHalfNo > 15)
		return MCDisassembler_Fail;

	if (MCOI->RegClass < 3) {
		Reg = getReg(Inst->MRI, MCOI->RegClass, RegNo);
	} else {
		Reg = getReg(Inst->MRI, MCOI->RegClass, RegHalfNo);
	}

	MCOperand_CreateReg0(Inst, Reg);

	return MCDisassembler_Success;
}

#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_DESC

#include "TriCoreGenInstrInfo.inc"

static const MCInstrDesc *get_desc(MCInst *MI)
{
	return TriCoreDescs.Insts +
	       (ARR_SIZE(TriCoreDescs.Insts) - 1 - MCInst_getOpcode(MI));
}

static DecodeStatus DecodeSBInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	unsigned disp8 = fieldFromInstruction_2(Insn, 8, 8);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	DecodeStatus status = MCDisassembler_Success;
	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 2) {
		tryDecodeReg(0, 15);
	}
	MCOperand_CreateImm0(Inst, disp8);

	return status;
}

static DecodeStatus DecodeSBRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned disp4 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 3) {
		tryDecodeReg(0, 15);
		tryDecodeReg(1, s2);
		MCOperand_CreateImm0(Inst, disp4);
	} else {
		tryDecodeReg(0, s2);
		MCOperand_CreateImm0(Inst, disp4);
	}

	return status;
}

static DecodeStatus DecodeSCInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	unsigned const8 = fieldFromInstruction_2(Insn, 8, 8);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	DecodeStatus status = MCDisassembler_Success;

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	switch (Insn & 0xff) {
	case 0xd8:
	case 0x58: {
		CS_ASSERT(desc->NumOperands == 3);
		tryDecodeReg(0, 15);
		tryDecodeReg(1, 10);
		decodeImm(const8);
		break;
	}
	case 0xf8:
	case 0x78: {
		CS_ASSERT(desc->NumOperands == 3);
		tryDecodeReg(0, 10);
		decodeImm(const8);
		tryDecodeReg(2, 15);
		break;
	}
	case 0x20:
	case 0x40: {
		//A[10], const8 (SC)
		CS_ASSERT(desc->NumOperands == 2);
		tryDecodeReg(0, 10);
		decodeImm(const8);
		break;
	}
	case 0x15:
	case 0xda:
	case 0x96:
	case 0x16:
	case 0xc6:
	case 0xd6: {
		CS_ASSERT(desc->NumOperands == 2);
		tryDecodeReg(0, 15);
		decodeImm(const8);
		break;
	}
	default:
		//		CS_ASSERT(desc->NumOperands == 1);
		decodeImm(const8);
		break;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned s1_d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands > 0) {
		status = DecodeRegisterClass(Inst, s1_d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;
	}

	if (desc->NumOperands > 1) {
		status = DecodeRegisterClass(Inst, s1_d, &desc->OpInfo[1]);
		if (status != MCDisassembler_Success)
			return status;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned const4 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	if (desc->NumOperands == 2) {
		tryDecodeReg(0, s1_d);
		MCOperand_CreateImm0(Inst, const4);
	} else if (desc->NumOperands == 3) {
		switch (Insn & 0xff) {
			//D[a], D[15], const4 (SRC)
		case 0x92:
		case 0x8a:
		case 0xca:
		case 0xaa:
		case 0xea: {
			tryDecodeReg(0, s1_d);
			tryDecodeReg(1, 15);
			MCOperand_CreateImm0(Inst, const4);
			break;
		}
		//D[15], D[a], const4 (SRC)
		case 0x9a:
		case 0xba:
		case 0xfa:
		case 0x86: {
			tryDecodeReg(0, 15);
			tryDecodeReg(1, s1_d);
			MCOperand_CreateImm0(Inst, const4);
			break;
		}
		}
	}

	return status;
}

static DecodeStatus DecodeSRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 2) {
		tryDecodeReg(0, s1_d);
		tryDecodeReg(1, s2);
	} else if (desc->NumOperands == 3) {
		switch (Insn & 0xff) {
		case 0x12:
		case 0x52:
		case 0x2a:
		case 0x6a:
		case 0xa:
		case 0x4a: {
			//D[a], D[15], D[b] (SRR)
			tryDecodeReg(0, s1_d);
			tryDecodeReg(1, 15);
			tryDecodeReg(2, s2);
			break;
		}
		case 0x1a:
		case 0x3a:
		case 0x5a:
		case 0x7a:
		case 0x6: {
			//D[15], D[a], D[b] (SRR)
			tryDecodeReg(0, 15);
			tryDecodeReg(1, s1_d);
			tryDecodeReg(2, s2);
			break;
		}
		}
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeABSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned off18_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off18_1 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off18_2 = fieldFromInstruction_4(Insn, 22, 4);
	unsigned off18_3 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned off18 = (off18_0 << 0) | (off18_1 << 6) | (off18_2 << 10) |
			 (off18_3 << 14);

	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	if (desc->NumOperands > 1) {
		if (desc->OpInfo[0].OperandType == MCOI_OPERAND_REGISTER) {
			status = DecodeRegisterClass(Inst, s1_d,
						     &desc->OpInfo[0]);
			if (status != MCDisassembler_Success)
				return status;

			MCOperand_CreateImm0(Inst, off18);
		} else {
			MCOperand_CreateImm0(Inst, off18);
			status = DecodeRegisterClass(Inst, s1_d,
						     &desc->OpInfo[0]);
			if (status != MCDisassembler_Success)
				return status;
		}
	} else {
		MCOperand_CreateImm0(Inst, off18);
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBInstruction(MCInst *Inst, unsigned Insn,
				       uint64_t Address, const void *Decoder)
{
	unsigned disp24_0 = fieldFromInstruction_4(Insn, 16, 16);
	unsigned disp24_1 = fieldFromInstruction_4(Insn, 8, 8);
	unsigned disp24 = (disp24_0 << 0) | (disp24_1 << 16);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	// Decode disp24.
	MCOperand_CreateImm0(Inst, disp24);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBOInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned off10_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off10_1 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off10 = (off10_0 << 0) | (off10_1 << 6);
	bool is_store = false;

	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	if (desc->NumOperands == 1) {
		return DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
	}

	switch (MCInst_getOpcode(Inst)) {
	case TriCore_ST_A_bo_r:
	case TriCore_ST_A_bo_c:
	case TriCore_ST_B_bo_r:
	case TriCore_ST_B_bo_c:
	case TriCore_ST_D_bo_r:
	case TriCore_ST_D_bo_c:
	case TriCore_ST_DA_bo_r:
	case TriCore_ST_DA_bo_c:
	case TriCore_ST_H_bo_r:
	case TriCore_ST_H_bo_c:
	case TriCore_ST_Q_bo_r:
	case TriCore_ST_Q_bo_c:
	case TriCore_ST_W_bo_r:
	case TriCore_ST_W_bo_c:
	case TriCore_SWAP_W_bo_r:
	case TriCore_SWAP_W_bo_c:
	case TriCore_SWAPMSK_W_bo_c:
	case TriCore_SWAPMSK_W_bo_r: {
		is_store = true;
		break;
	}
	}

	if (desc->NumOperands == 2) {
		if (desc->OpInfo[1].OperandType == MCOI_OPERAND_REGISTER) {
			// we have [reg+r] instruction
			if (is_store) {
				status = DecodeRegisterClass(Inst, s2,
							     &desc->OpInfo[0]);
				if (status != MCDisassembler_Success)
					return status;
				return DecodeRegisterClass(Inst, s1_d,
							   &desc->OpInfo[1]);
			} else {
				status = DecodeRegisterClass(Inst, s1_d,
							     &desc->OpInfo[0]);
				if (status != MCDisassembler_Success)
					return status;
				return DecodeRegisterClass(Inst, s2,
							   &desc->OpInfo[1]);
			}
		} else {
			// we have one of the CACHE instructions without destination reg
			status =
				DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
			if (status != MCDisassembler_Success)
				return status;

			MCOperand_CreateImm0(Inst, off10);
		}
		return MCDisassembler_Success;
	}

	if (desc->NumOperands > 2) {
		if (is_store) {
			// we have [reg+c] instruction
			status =
				DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
			if (status != MCDisassembler_Success)
				return status;

			status = DecodeRegisterClass(Inst, s1_d,
						     &desc->OpInfo[1]);
			if (status != MCDisassembler_Success)
				return status;
		} else {
			status = DecodeRegisterClass(Inst, s1_d,
						     &desc->OpInfo[0]);
			if (status != MCDisassembler_Success)
				return status;

			status =
				DecodeRegisterClass(Inst, s2, &desc->OpInfo[1]);
			if (status != MCDisassembler_Success)
				return status;
		}
		MCOperand_CreateImm0(Inst, off10);
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBOLInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned off16_0 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off16_1 = fieldFromInstruction_4(Insn, 22, 6);
	unsigned off16_2 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off16 = (off16_0 << 0) | (off16_1 << 10) | (off16_2 << 6);

	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	switch (MCInst_getOpcode(Inst)) {
	case TriCore_LD_A_bol:
	case TriCore_LD_B_bol:
	case TriCore_LD_BU_bol:
	case TriCore_LD_H_bol:
	case TriCore_LD_HU_bol:
	case TriCore_LD_W_bol:
	case TriCore_LEA_bol: {
		// Decode s1_d.
		status = DecodeRegisterClass(Inst, s1_d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		// Decode s2.
		status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[1]);
		if (status != MCDisassembler_Success)
			return status;
		break;
	}
	case TriCore_ST_A_bol:
	case TriCore_ST_B_bol:
	case TriCore_ST_H_bol:
	case TriCore_ST_W_bol: {
		// Decode s2.
		status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		// Decode s1_d.
		status = DecodeRegisterClass(Inst, s1_d, &desc->OpInfo[1]);
		if (status != MCDisassembler_Success)
			return status;
		break;
	}
	default:
		return MCDisassembler_Fail;
	}

	// Decode off16.
	MCOperand_CreateImm0(Inst, off16);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned const9 = fieldFromInstruction_4(Insn, 12, 9);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands > 1) {
		// Decode d.
		status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		// Decode s1.
		status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
		if (status != MCDisassembler_Success)
			return status;
	}

	// Decode const9.
	MCOperand_CreateImm0(Inst, const9);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCPWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned pos = fieldFromInstruction_4(Insn, 23, 5);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	// Decode d.
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
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
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned const16 = fieldFromInstruction_4(Insn, 12, 16);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 3) {
		status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
		if (status != MCDisassembler_Success)
			return status;

		MCOperand_CreateImm0(Inst, const16);

		return MCDisassembler_Success;
	}

	if (desc->OpInfo[0].OperandType == MCOI_OPERAND_REGISTER) {
		status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		MCOperand_CreateImm0(Inst, const16);
	} else {
		MCOperand_CreateImm0(Inst, const16);
		if (MCInst_getOpcode(Inst) == TriCore_MTCR_rlc) {
			status =
				DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
		} else {
			status = DecodeRegisterClass(Inst, d, &desc->OpInfo[1]);
		}
		if (status != MCDisassembler_Success)
			return status;
	}
	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRInstruction(MCInst *Inst, unsigned Insn,
					uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned n = fieldFromInstruction_4(Insn, 16, 2);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	/// But even if the instruction is in RR format and has only one operand,
	/// we cannot be sure whether the operand is s1 or s2
	if (desc->NumOperands == 1) {
		if (desc->OpInfo[0].OperandType == MCOI_OPERAND_REGISTER) {
			switch (MCInst_getOpcode(Inst)) {
			case TriCore_CALLI_rr_v110: {
				return DecodeRegisterClass(Inst, s2,
							   &desc->OpInfo[0]);
			}
			default: {
				return DecodeRegisterClass(Inst, s1,
							   &desc->OpInfo[0]);
			}
			}
		}
		return MCDisassembler_Fail;
	}

	if (desc->NumOperands > 0) {
		// Decode d.
		status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;
	}

	if (desc->NumOperands > 1) {
		if (desc->OpInfo[0].OperandType == MCOI_OPERAND_REGISTER) {
			switch (MCInst_getOpcode(Inst)) {
			case TriCore_ABSS_rr:
			case TriCore_ABSS_H_rr:
			case TriCore_ABS_H_rr:
			case TriCore_ABS_B_rr:
			case TriCore_ABS_rr: {
				status = DecodeRegisterClass(Inst, s2,
							     &desc->OpInfo[1]);
				break;
			}
			default:
				status = DecodeRegisterClass(Inst, s1,
							     &desc->OpInfo[1]);
			}
			if (status != MCDisassembler_Success)
				return status;
		}
	}

	if (desc->NumOperands > 2) {
		status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
		if (status != MCDisassembler_Success)
			return status;
	}

	if (desc->NumOperands > 3) {
		MCOperand_CreateImm0(Inst, n);
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRR2Instruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	// Decode d.
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRPWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status;
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);
	unsigned pos = fieldFromInstruction_4(Insn, 23, 5);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);

	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	tryDecodeReg(0, d);
	tryDecodeReg(1, s1);
	tryDecodeReg(2, s2);
	decodeImm(pos);
	decodeImm(width);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSLRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	// Decode d.
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSLROInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned off4 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	tryDecodeReg(0, d);
	if (desc->NumOperands == 3) {
		tryDecodeReg(1, 15);
	}
	decodeImm(off4);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSROInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned off4 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	switch (Insn & 0xff) {
	case 0xcc:
	case 0x0c:
	case 0x8c:
	case 0x4c:
	case 0x48:
	case 0xc8:
	case 0x8:
	case 0x88:
	case 0x28: {
		tryDecodeReg(0, 15);
		tryDecodeReg(1, s2);
		MCOperand_CreateImm0(Inst, off4);
		break;
	}
	case 0xec:
	case 0x2c:
	case 0xac:
	case 0x6c:
	case 0x18:
	case 0xa8:
	case 0x68:
	case 0xe8: {
		tryDecodeReg(0, s2);
		MCOperand_CreateImm0(Inst, off4);
		tryDecodeReg(2, 15);
		break;
	}
	default: {
		tryDecodeReg(0, s2);
		MCOperand_CreateImm0(Inst, off4);
		break;
	}
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSRRSInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned n = fieldFromInstruction_2(Insn, 6, 2);
	unsigned s1_d = fieldFromInstruction_2(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	tryDecodeReg(0, s1_d);
	tryDecodeReg(1, s2);
	if (desc->NumOperands == 4) {
		tryDecodeReg(2, 15);
	}
	MCOperand_CreateImm0(Inst, n);

	return status;
}

static DecodeStatus DecodeSBCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	unsigned disp4 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned const4 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	DecodeStatus status = MCDisassembler_Success;
	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 3) {
		tryDecodeReg(0, 15);
		decodeImm(disp4);
		decodeImm(const4);
	} else if (desc->NumOperands == 2) {
		decodeImm(disp4);
		decodeImm(const4);
		status = MCDisassembler_Success;
	}

	return status;
}

static DecodeStatus DecodeSBRNInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	unsigned disp4 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned n = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	DecodeStatus status = MCDisassembler_Success;
	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands == 3) {
		tryDecodeReg(0, 15);
	}

	// Decode n.
	MCOperand_CreateImm0(Inst, n);
	// Decode disp4.
	MCOperand_CreateImm0(Inst, disp4);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSSRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSSROInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_2(Insn, 8, 4);
	unsigned off4 = fieldFromInstruction_2(Insn, 12, 4);
	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (is32Bit) // This instruction is 16-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	CS_ASSERT_RET_VAL(desc->NumOperands == 3, MCDisassembler_Fail);

	tryDecodeReg(0, 15);
	tryDecodeReg(1, s1);
	MCOperand_CreateImm0(Inst, off4);

	return MCDisassembler_Success;
}

/// 32-bit Opcode Format

static DecodeStatus DecodeSYSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1_d = fieldFromInstruction_4(Insn, 8, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (desc->NumOperands > 0) {
		status = DecodeRegisterClass(Inst, s1_d, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRR2Instruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRR1Instruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned n = fieldFromInstruction_4(Insn, 16, 2);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode n.
	MCOperand_CreateImm0(Inst, n);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBITInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned pos1 = fieldFromInstruction_4(Insn, 16, 5);
	unsigned pos2 = fieldFromInstruction_4(Insn, 23, 5);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode pos1.
	MCOperand_CreateImm0(Inst, pos1);

	// Decode pos2.
	MCOperand_CreateImm0(Inst, pos2);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRR1Instruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned n = fieldFromInstruction_4(Insn, 16, 2);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode n.
	MCOperand_CreateImm0(Inst, n);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned const9 = fieldFromInstruction_4(Insn, 12, 9);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const9.
	MCOperand_CreateImm0(Inst, const9);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRRWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode width.
	MCOperand_CreateImm0(Inst, width);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRCRRInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRRRInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	if (desc->NumOperands == 3) {
		switch (MCInst_getOpcode(Inst)) {
		case TriCore_EXTR_rrrr:
		case TriCore_EXTR_U_rrrr:
			return DecodeRegisterClass(Inst, s3, &desc->OpInfo[2]);
		default:
			return DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
		}
	}

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;
	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned disp15 = fieldFromInstruction_4(Insn, 16, 15);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	if (MCInst_getOpcode(Inst) == TriCore_LOOP_brr) {
		status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		MCOperand_CreateImm0(Inst, disp15);
		return MCDisassembler_Success;
	}

	if (desc->NumOperands >= 2) {
		status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[0]);
		if (status != MCDisassembler_Success)
			return status;

		if (desc->NumOperands >= 3) {
			status =
				DecodeRegisterClass(Inst, s2, &desc->OpInfo[1]);
			if (status != MCDisassembler_Success)
				return status;
		}
	}

	// Decode disp15.
	MCOperand_CreateImm0(Inst, disp15);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBRCInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned disp15 = fieldFromInstruction_4(Insn, 16, 15);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode const4.
	MCOperand_CreateImm0(Inst, const4);

	// Decode disp15.
	MCOperand_CreateImm0(Inst, disp15);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRRRInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned s2 = fieldFromInstruction_4(Insn, 12, 4);
	//	unsigned n = fieldFromInstruction_4(Insn, 16, 2);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, d, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s1.
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[1]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s2.
	status = DecodeRegisterClass(Inst, s2, &desc->OpInfo[2]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode s3.
	status = DecodeRegisterClass(Inst, s3, &desc->OpInfo[3]);
	if (status != MCDisassembler_Success)
		return status;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeABSBInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	unsigned bpos3 = fieldFromInstruction_4(Insn, 8, 3);
	unsigned b = fieldFromInstruction_4(Insn, 12, 1);

	unsigned off18_0_5 = fieldFromInstruction_4(Insn, 16, 6);
	unsigned off18_6_9 = fieldFromInstruction_4(Insn, 28, 4);
	unsigned off18_10_13 = fieldFromInstruction_4(Insn, 22, 4);
	unsigned off18_14_17 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned off18 = (off18_0_5 << 0) | (off18_6_9 << 6) |
			 (off18_10_13 << 10) | (off18_14_17 << 14);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	decodeImm(off18) decodeImm(bpos3) decodeImm(b)

		return MCDisassembler_Success;
}

static DecodeStatus DecodeRCRWInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);
	unsigned const4 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned width = fieldFromInstruction_4(Insn, 16, 5);
	unsigned s3 = fieldFromInstruction_4(Insn, 24, 4);
	unsigned d = fieldFromInstruction_4(Insn, 28, 4);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	tryDecodeReg(0, d);
	tryDecodeReg(1, s1);
	tryDecodeReg(2, s3);
	decodeImm(const4);
	decodeImm(width);

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBRNInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address, const void *Decoder)
{
	DecodeStatus status = MCDisassembler_Success;
	unsigned s1 = fieldFromInstruction_4(Insn, 8, 4);

	unsigned n_0_3 = fieldFromInstruction_4(Insn, 12, 4);
	unsigned n_4 = fieldFromInstruction_4(Insn, 7, 1);
	unsigned n = (n_0_3 << 0) | (n_4 << 4);

	unsigned disp15 = fieldFromInstruction_4(Insn, 16, 15);

	unsigned is32Bit = fieldFromInstruction_4(Insn, 0, 1);
	if (!is32Bit) // This instruction is 32-bit
		return MCDisassembler_Fail;

	const MCInstrDesc *desc = get_desc(Inst);
	status = DecodeRegisterClass(Inst, s1, &desc->OpInfo[0]);
	if (status != MCDisassembler_Success)
		return status;

	// Decode n.
	MCOperand_CreateImm0(Inst, n);

	// Decode disp15.
	MCOperand_CreateImm0(Inst, disp15);

	return MCDisassembler_Success;
}

#define GET_SUBTARGETINFO_ENUM

#include "TriCoreGenInstrInfo.inc"

static inline bool decodeInstruction2_or_4(const uint8_t *code, size_t code_len,
					   MCInst *MI, uint16_t *size,
					   uint64_t address,
					   const uint8_t *tbl2,
					   const uint8_t *tbl4)
{
	if (tbl2) {
		if (code_len < 2) {
			return false;
		}
		uint16_t insn2 = readBytes16(MI, code);
		DecodeStatus Result =
			decodeInstruction_2(tbl2, MI, insn2, address, NULL);
		if (Result == MCDisassembler_Success) {
			*size = 2;
			return true;
		}
	}

	if (tbl4) {
		if (code_len < 4) {
			return false;
		}
		uint32_t insn4 = readBytes32(MI, code);
		DecodeStatus Result =
			decodeInstruction_4(tbl4, MI, insn4, address, NULL);
		if (Result == MCDisassembler_Success) {
			*size = 4;
			return true;
		}
	}
	return false;
}

static bool getInstruction(csh ud, const uint8_t *code, size_t code_len,
			   MCInst *MI, uint16_t *size, uint64_t address)
{
	if (!ud) {
		return false;
	}

	struct cs_struct *cs = (struct cs_struct *)ud;
	switch (cs->mode) {
	case CS_MODE_TRICORE_110: {
		if (decodeInstruction2_or_4(code, code_len, MI, size, address,
					    DecoderTablev11016,
					    DecoderTablev11032)) {
			return true;
		}
		break;
	}
	default:
		break;
	}

	return decodeInstruction2_or_4(code, code_len, MI, size, address,
				       DecoderTable16, DecoderTable32);
}

bool TriCore_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				 size_t ByteLen, MCInst *MI, uint16_t *Size,
				 uint64_t Address)
{
	return getInstruction(handle, Bytes, ByteLen, MI, Size, Address);
}

void TriCore_init_mri(MCRegisterInfo *MRI)
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

	MCRegisterInfo_InitMCRegisterInfo(
		MRI, TriCoreRegDesc, ARR_SIZE(TriCoreRegDesc), 0, 0,
		TriCoreMCRegisterClasses, ARR_SIZE(TriCoreMCRegisterClasses), 0,
		0, TriCoreRegDiffLists, 0, TriCoreSubRegIdxLists,
		ARR_SIZE(TriCoreSubRegIdxLists), TriCoreRegEncodingTable);
}

#endif
