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

//===-- RISCVDisassembler.cpp - Disassembler for RISC-V -------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the RISCVDisassembler class.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInst.h"
#include "../../MathExtras.h"
#include "../../MCInstPrinter.h"
#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../cs_priv.h"
#include "../../utils.h"
#include "RISCVDisassemblerExtension.h"
#include "RISCVBaseInfo.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

#define GET_REGINFO_ENUM
#include "RISCVGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_DESC
#include "RISCVGenInstrInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "riscv-disassembler"

DecodeStatus RISCV_getInstruction(MCInst *Instr, uint16_t *Size,
				  const uint8_t *Bytes, size_t BytesLen,
				  uint64_t Address, SStream *CStream);
void addSPOperands(MCInst *MI);
;
// end anonymous namespace

static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, uint32_t RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	bool IsRVE = RISCV_getFeatureBits(Inst->csh->mode, RISCV_FeatureRVE);

	if (RegNo >= 32 || (IsRVE && RegNo >= 16))
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_X0 + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRX1X5RegisterClass(MCInst *Inst, uint32_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	MCRegister Reg = RISCV_X0 + RegNo;
	if (Reg != RISCV_X1 && Reg != RISCV_X5)
		return MCDisassembler_Fail;

	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR16RegisterClass(MCInst *Inst, uint32_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo >= 32)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_F0_H + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR32RegisterClass(MCInst *Inst, uint32_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo >= 32)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_F0_F + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR32CRegisterClass(MCInst *Inst, uint32_t RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo >= 8) {
		return MCDisassembler_Fail;
	}
	MCRegister Reg = RISCV_F8_F + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR64RegisterClass(MCInst *Inst, uint32_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo >= 32)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_F0_D + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR64CRegisterClass(MCInst *Inst, uint32_t RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo >= 8) {
		return MCDisassembler_Fail;
	}
	MCRegister Reg = RISCV_F8_D + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNoX0RegisterClass(MCInst *Inst, uint32_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo == 0) {
		return MCDisassembler_Fail;
	}

	return DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeGPRNoX0X2RegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint32_t Address,
						 const void *Decoder)
{
	if (RegNo == 2) {
		return MCDisassembler_Fail;
	}

	return DecodeGPRNoX0RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, uint32_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= 8)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_X8 + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRPairRegisterClass(MCInst *Inst, uint32_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo >= 32 || RegNo & 1)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_X0 + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSR07RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= 8)
		return MCDisassembler_Fail;

	MCRegister Reg = (RegNo < 2) ? (RegNo + RISCV_X8) :
				       (RegNo - 2 + RISCV_X18);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeVRRegisterClass(MCInst *Inst, uint32_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= 32)
		return MCDisassembler_Fail;

	MCRegister Reg = RISCV_V0 + RegNo;
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeVRM2RegisterClass(MCInst *Inst, uint32_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= 32 || RegNo % 2)
		return MCDisassembler_Fail;

	MCRegister Reg = MCRegisterInfo_getMatchingSuperReg(
		Inst->MRI, RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
		MCRegisterInfo_getRegClass(Inst->MRI, RISCV_VRM2RegClassID));

	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeVRM4RegisterClass(MCInst *Inst, uint32_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= 32 || RegNo % 4)
		return MCDisassembler_Fail;

	MCRegister Reg = MCRegisterInfo_getMatchingSuperReg(
		Inst->MRI, RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
		MCRegisterInfo_getRegClass(Inst->MRI, RISCV_VRM4RegClassID));

	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeVRM8RegisterClass(MCInst *Inst, uint32_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= 32 || RegNo % 8)
		return MCDisassembler_Fail;

	MCRegister Reg = MCRegisterInfo_getMatchingSuperReg(
		Inst->MRI, RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
		MCRegisterInfo_getRegClass(Inst->MRI, RISCV_VRM8RegClassID));

	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus decodeVMaskReg(MCInst *Inst, uint64_t RegNo,
				   uint64_t Address, const void *Decoder)
{
	if (RegNo > 2) {
		return MCDisassembler_Fail;
	}
	MCRegister Reg = (RegNo == 0) ? RISCV_V0 : RISCV_NoRegister;

	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

#define DEFINE_decodeUImmOperand(N) \
	static DecodeStatus CONCAT(decodeUImmOperand, \
				   N)(MCInst * Inst, uint32_t Imm, \
				      int64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(isUIntN(N, Imm) && "Invalid immediate"); \
		MCOperand_CreateImm0(Inst, (Imm)); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeUImmOperand(6);
DEFINE_decodeUImmOperand(2);
DEFINE_decodeUImmOperand(8);
DEFINE_decodeUImmOperand(9);
DEFINE_decodeUImmOperand(7);
DEFINE_decodeUImmOperand(4);
DEFINE_decodeUImmOperand(20);
DEFINE_decodeUImmOperand(5);
DEFINE_decodeUImmOperand(11);
DEFINE_decodeUImmOperand(10);
DEFINE_decodeUImmOperand(12);
DEFINE_decodeUImmOperand(3);
DEFINE_decodeUImmOperand(1);

#define DEFINE_decodeUImmNonZeroOperand(N) \
	static DecodeStatus CONCAT(decodeUImmNonZeroOperand, \
				   N)(MCInst * Inst, uint32_t Imm, \
				      int64_t Address, const void *Decoder) \
	{ \
		if (Imm == 0) \
			return MCDisassembler_Fail; \
		return CONCAT(decodeUImmOperand, N)(Inst, Imm, Address, \
						    Decoder); \
	}
DEFINE_decodeUImmNonZeroOperand(10);

#define DEFINE_decodeSImmOperand(N) \
	static DecodeStatus CONCAT(decodeSImmOperand, \
				   N)(MCInst * Inst, uint32_t Imm, \
				      int64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(isUIntN(N, Imm) && "Invalid immediate"); \
\
		MCOperand_CreateImm0(Inst, (SignExtend64((Imm), N))); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeSImmOperand(6);
DEFINE_decodeSImmOperand(12);
DEFINE_decodeSImmOperand(5);
DEFINE_decodeSImmOperand(10);

#define DEFINE_decodeSImmNonZeroOperand(N) \
	static DecodeStatus CONCAT(decodeSImmNonZeroOperand, \
				   N)(MCInst * Inst, uint32_t Imm, \
				      int64_t Address, const void *Decoder) \
	{ \
		if (Imm == 0) \
			return MCDisassembler_Fail; \
		return CONCAT(decodeSImmOperand, N)(Inst, Imm, Address, \
						    Decoder); \
	}
DEFINE_decodeSImmNonZeroOperand(6);
DEFINE_decodeSImmNonZeroOperand(10);

#define DEFINE_decodeSImmOperandAndLsl1(N) \
	static DecodeStatus CONCAT(decodeSImmOperandAndLsl1, \
				   N)(MCInst * Inst, uint32_t Imm, \
				      int64_t Address, const void *Decoder) \
	{ \
		CS_ASSERT(isUIntN(N, Imm) && "Invalid immediate"); \
\
		MCOperand_CreateImm0(Inst, (SignExtend64((Imm << 1), N))); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeSImmOperandAndLsl1(12);
DEFINE_decodeSImmOperandAndLsl1(9);
DEFINE_decodeSImmOperandAndLsl1(13);
DEFINE_decodeSImmOperandAndLsl1(21);

static DecodeStatus decodeCLUIImmOperand(MCInst *Inst, uint32_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT(isUIntN(6, Imm) && "Invalid immediate");
	if (Imm > 31) {
		Imm = (SignExtend64((Imm), 6) & 0xfffff);
	}
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeFRMArg(MCInst *Inst, uint32_t Imm, int64_t Address,
				 const void *Decoder)
{
	CS_ASSERT(isUIntN(3, Imm) && "Invalid immediate");
	if (!RISCVFPRndMode_isValidRoundingMode(Imm))
		return MCDisassembler_Fail;

	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs1ImmZero(MCInst *Inst, uint32_t Insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus decodeRVCInstrRdSImm(MCInst *Inst, uint32_t Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus decodeRVCInstrRdRs1UImm(MCInst *Inst, uint32_t Insn,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus decodeRVCInstrRdRs2(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus decodeRVCInstrRdRs1Rs2(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus decodeXTHeadMemPair(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus decodeZcmpRlist(MCInst *Inst, unsigned Imm,
				    uint64_t Address, const void *Decoder);

static DecodeStatus decodeRegReg(MCInst *Inst, uint32_t Insn, uint64_t Address,
				 const void *Decoder);

static DecodeStatus decodeZcmpSpimm(MCInst *Inst, unsigned Imm,
				    uint64_t Address, const void *Decoder);

static DecodeStatus decodeCSSPushPopchk(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus decodeUImmLog2XLenOperand(MCInst *Inst, uint32_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT(isUIntN(6, Imm) && "Invalid immediate");

	if (!RISCV_getFeatureBits(Inst->csh->mode, RISCV_Feature64Bit) &&
	    !isUIntN(5, Imm))
		return MCDisassembler_Fail;

	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeUImmLog2XLenNonZeroOperand(MCInst *Inst, uint32_t Imm,
						     int64_t Address,
						     const void *Decoder)
{
	if (Imm == 0)
		return MCDisassembler_Fail;
	return decodeUImmLog2XLenOperand(Inst, Imm, Address, Decoder);
}

#include "RISCVGenDisassemblerTables.inc"

static DecodeStatus decodeRVCInstrRdRs1ImmZero(MCInst *Inst, uint32_t Insn,
					       uint64_t Address,
					       const void *Decoder)
{
	uint32_t Rd = fieldFromInstruction_4(Insn, 7, 5);
	DecodeStatus Result =
		DecodeGPRNoX0RegisterClass(Inst, Rd, Address, Decoder);
	(void)Result;
	CS_ASSERT(Result == MCDisassembler_Success && "Invalid register");
	MCInst_addOperand2(Inst, (MCInst_getOperand(Inst, (0))));
	MCOperand_CreateImm0(Inst, (0));
	return MCDisassembler_Success;
}

static DecodeStatus decodeCSSPushPopchk(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder)
{
	uint32_t Rs1 = fieldFromInstruction_4(Insn, 7, 5);
	DecodeStatus Result =
		DecodeGPRX1X5RegisterClass(Inst, Rs1, Address, Decoder);
	(void)Result;
	CS_ASSERT(Result == MCDisassembler_Success && "Invalid register");
	return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdSImm(MCInst *Inst, uint32_t Insn,
					 uint64_t Address, const void *Decoder)
{
	MCOperand_CreateReg0(Inst, (RISCV_X0));
	uint32_t SImm6 = fieldFromInstruction_4(Insn, 12, 1) << 5 |
			 fieldFromInstruction_4(Insn, 2, 5);
	DecodeStatus Result =
		CONCAT(decodeSImmOperand, 6)(Inst, SImm6, Address, Decoder);
	(void)Result;
	CS_ASSERT(Result == MCDisassembler_Success && "Invalid immediate");
	return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs1UImm(MCInst *Inst, uint32_t Insn,
					    uint64_t Address,
					    const void *Decoder)
{
	MCOperand_CreateReg0(Inst, (RISCV_X0));
	MCInst_addOperand2(Inst, (MCInst_getOperand(Inst, (0))));
	uint32_t UImm6 = fieldFromInstruction_4(Insn, 12, 1) << 5 |
			 fieldFromInstruction_4(Insn, 2, 5);
	DecodeStatus Result =
		CONCAT(decodeUImmOperand, 6)(Inst, UImm6, Address, Decoder);
	(void)Result;
	CS_ASSERT(Result == MCDisassembler_Success && "Invalid immediate");
	return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs2(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder)
{
	uint32_t Rd = fieldFromInstruction_4(Insn, 7, 5);
	uint32_t Rs2 = fieldFromInstruction_4(Insn, 2, 5);
	DecodeGPRRegisterClass(Inst, Rd, Address, Decoder);
	DecodeGPRRegisterClass(Inst, Rs2, Address, Decoder);
	return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs1Rs2(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	uint32_t Rd = fieldFromInstruction_4(Insn, 7, 5);
	uint32_t Rs2 = fieldFromInstruction_4(Insn, 2, 5);
	DecodeGPRRegisterClass(Inst, Rd, Address, Decoder);
	MCInst_addOperand2(Inst, (MCInst_getOperand(Inst, (0))));
	DecodeGPRRegisterClass(Inst, Rs2, Address, Decoder);
	return MCDisassembler_Success;
}

static DecodeStatus decodeXTHeadMemPair(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder)
{
	uint32_t Rd1 = fieldFromInstruction_4(Insn, 7, 5);
	uint32_t Rs1 = fieldFromInstruction_4(Insn, 15, 5);
	uint32_t Rd2 = fieldFromInstruction_4(Insn, 20, 5);
	uint32_t UImm2 = fieldFromInstruction_4(Insn, 25, 2);
	DecodeGPRRegisterClass(Inst, Rd1, Address, Decoder);
	DecodeGPRRegisterClass(Inst, Rd2, Address, Decoder);
	DecodeGPRRegisterClass(Inst, Rs1, Address, Decoder);
	DecodeStatus Result =
		CONCAT(decodeUImmOperand, 2)(Inst, UImm2, Address, Decoder);
	(void)Result;
	CS_ASSERT(Result == MCDisassembler_Success && "Invalid immediate");

	// Disassemble the final operand which is implicit.
	unsigned Opcode = MCInst_getOpcode(Inst);
	bool IsWordOp = (Opcode == RISCV_TH_LWD || Opcode == RISCV_TH_LWUD ||
			 Opcode == RISCV_TH_SWD);
	if (IsWordOp)
		MCOperand_CreateImm0(Inst, (3));
	else
		MCOperand_CreateImm0(Inst, (4));

	return MCDisassembler_Success;
}

static DecodeStatus decodeZcmpRlist(MCInst *Inst, unsigned Imm,
				    uint64_t Address, const void *Decoder)
{
	if (Imm <= 3)
		return MCDisassembler_Fail;
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeRegReg(MCInst *Inst, uint32_t Insn, uint64_t Address,
				 const void *Decoder)
{
	uint32_t Rs1 = fieldFromInstruction_4(Insn, 0, 5);
	uint32_t Rs2 = fieldFromInstruction_4(Insn, 5, 5);
	DecodeGPRRegisterClass(Inst, Rs1, Address, Decoder);
	DecodeGPRRegisterClass(Inst, Rs2, Address, Decoder);
	return MCDisassembler_Success;
}

static DecodeStatus decodeZcmpSpimm(MCInst *Inst, unsigned Imm,
				    uint64_t Address, const void *Decoder)
{
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

// Add implied SP operand for C.*SP compressed instructions. The SP operand
// isn't explicitly encoded in the instruction.
void addSPOperands(MCInst *MI)
{
	const MCInstrDesc *MCID = MCInstrDesc_get(MCInst_getOpcode(MI),
						  RISCVDescs.Insts,
						  ARR_SIZE(RISCVDescs.Insts));
	MCOperand SPReg;
	SPReg.MachineOperandType = kRegister;
	SPReg.Kind = kRegister;
	SPReg.RegVal = RISCV_X2;
	for (unsigned i = 0; i < MCID->NumOperands; i++)
		if (MCID->OpInfo[i].RegClass == RISCV_SPRegClassID)
			MCInst_insert0(MI, i, &SPReg);
}

DecodeStatus RISCV_getInstruction(MCInst *MI, uint16_t *Size,
				  const uint8_t *Bytes, size_t BytesLen,
				  uint64_t Address, SStream *CS)
{
	// TODO: This will need modification when supporting instruction set
	// extensions with instructions > 32-bits (up to 176 bits wide).
	uint32_t Insn;
	DecodeStatus Result;

#define TRY_TO_DECODE_WITH_ADDITIONAL_OPERATION( \
	width, FEATURE_CHECKS, DECODER_TABLE, DESC, ADDITIONAL_OPERATION) \
	do { \
		if (FEATURE_CHECKS) { \
			Result = decodeInstruction_##width( \
				DECODER_TABLE, MI, Insn, Address, NULL); \
			if (Result != MCDisassembler_Fail) { \
				ADDITIONAL_OPERATION; \
				return Result; \
			} \
		} \
	} while (false)
#define TRY_TO_DECODE_AND_ADD_SP(width, FEATURE_CHECKS, DECODER_TABLE, DESC) \
	TRY_TO_DECODE_WITH_ADDITIONAL_OPERATION( \
		width, FEATURE_CHECKS, DECODER_TABLE, DESC, addSPOperands(MI))
#define TRY_TO_DECODE(width, FEATURE_CHECKS, DECODER_TABLE, DESC) \
	TRY_TO_DECODE_WITH_ADDITIONAL_OPERATION( \
		width, FEATURE_CHECKS, DECODER_TABLE, DESC, (void)NULL)
#define TRY_TO_DECODE_FEATURE(width, FEATURE, DECODER_TABLE, DESC) \
	TRY_TO_DECODE(width, RISCV_getFeatureBits(MI->csh->mode, FEATURE), \
		      DECODER_TABLE, DESC)

	// It's a 32 bit instruction if bit 0 and 1 are 1.
	if ((Bytes[0] & 0x3) == 0x3) {
		if (BytesLen < 4) {
			*Size = 0;
			return MCDisassembler_Fail;
		}
		*Size = 4;

		Insn = readBytes32(MI, Bytes);

		TRY_TO_DECODE(4,
			      RISCV_getFeatureBits(MI->csh->mode,
						   RISCV_FeatureStdExtZdinx) &&
				      !RISCV_getFeatureBits(MI->csh->mode,
							    RISCV_Feature64Bit),
			      DecoderTableRV32Zdinx32,
			      "RV32Zdinx table (Double in Integer and rv32)");
		TRY_TO_DECODE(4,
			      RISCV_getFeatureBits(MI->csh->mode,
						   RISCV_FeatureStdExtZacas) &&
				      !RISCV_getFeatureBits(MI->csh->mode,
							    RISCV_Feature64Bit),
			      DecoderTableRV32Zacas32,
			      "RV32Zacas table (Compare-And-Swap and rv32)");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureStdExtZfinx,
				      DecoderTableRVZfinx32,
				      "RVZfinx table (Float in Integer)");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXVentanaCondOps,
				      DecoderTableXVentana32,
				      "Ventana custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadBa,
				      DecoderTableXTHeadBa32,
				      "XTHeadBa custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadBb,
				      DecoderTableXTHeadBb32,
				      "XTHeadBb custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadBs,
				      DecoderTableXTHeadBs32,
				      "XTHeadBs custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadCondMov,
				      DecoderTableXTHeadCondMov32,
				      "XTHeadCondMov custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadCmo,
				      DecoderTableXTHeadCmo32,
				      "XTHeadCmo custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadFMemIdx,
				      DecoderTableXTHeadFMemIdx32,
				      "XTHeadFMemIdx custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadMac,
				      DecoderTableXTHeadMac32,
				      "XTHeadMac custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadMemIdx,
				      DecoderTableXTHeadMemIdx32,
				      "XTHeadMemIdx custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadMemPair,
				      DecoderTableXTHeadMemPair32,
				      "XTHeadMemPair custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadSync,
				      DecoderTableXTHeadSync32,
				      "XTHeadSync custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXTHeadVdot,
				      DecoderTableXTHeadVdot32,
				      "XTHeadVdot custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXSfvcp,
				      DecoderTableXSfvcp32,
				      "SiFive VCIX custom opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXSfvqmaccdod,
			DecoderTableXSfvqmaccdod32,
			"SiFive Matrix Multiplication (2x8 and 8x2) Instruction opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXSfvqmaccqoq,
			DecoderTableXSfvqmaccqoq32,
			"SiFive Matrix Multiplication (4x8 and 8x4) Instruction opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXSfvfwmaccqqq,
			DecoderTableXSfvfwmaccqqq32,
			"SiFive Matrix Multiplication Instruction opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXSfvfnrclipxfqf,
			DecoderTableXSfvfnrclipxfqf32,
			"SiFive FP32-to-int8 Ranged Clip Instructions opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXCVbitmanip,
			DecoderTableXCVbitmanip32,
			"CORE-V Bit Manipulation custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXCVelw,
				      DecoderTableXCVelw32,
				      "CORE-V Event load custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXCVmac,
				      DecoderTableXCVmac32,
				      "CORE-V MAC custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXCVmem,
				      DecoderTableXCVmem32,
				      "CORE-V MEM custom opcode table");
		TRY_TO_DECODE_FEATURE(4, RISCV_FeatureVendorXCValu,
				      DecoderTableXCValu32,
				      "CORE-V ALU custom opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXCVsimd, DecoderTableXCVsimd32,
			"CORE-V SIMD extensions custom opcode table");
		TRY_TO_DECODE_FEATURE(
			4, RISCV_FeatureVendorXCVbi, DecoderTableXCVbi32,
			"CORE-V Immediate Branching custom opcode table");
		TRY_TO_DECODE(4, true, DecoderTable32, "RISCV32 table");

		return MCDisassembler_Fail;
	}

	if (BytesLen < 2) {
		*Size = 0;
		return MCDisassembler_Fail;
	}
	*Size = 2;

	Insn = readBytes16(MI, Bytes);
	TRY_TO_DECODE_AND_ADD_SP(
		2, !RISCV_getFeatureBits(MI->csh->mode, RISCV_Feature64Bit),
		DecoderTableRISCV32Only_16,
		"RISCV32Only_16 table (16-bit Instruction)");
	TRY_TO_DECODE_FEATURE(2, RISCV_FeatureStdExtZicfiss,
			      DecoderTableZicfiss16,
			      "RVZicfiss table (Shadow Stack)");
	TRY_TO_DECODE_FEATURE(2, RISCV_FeatureStdExtZcmt, DecoderTableRVZcmt16,
			      "Zcmt table (16-bit Table Jump Instructions)");
	TRY_TO_DECODE_FEATURE(
		2, RISCV_FeatureStdExtZcmp, DecoderTableRVZcmp16,
		"Zcmp table (16-bit Push/Pop & Double Move Instructions)");
	TRY_TO_DECODE_AND_ADD_SP(2, true, DecoderTable16,
				 "RISCV_C table (16-bit Instruction)");

	return MCDisassembler_Fail;
}

bool RISCV_LLVM_getInstruction(csh handle, const uint8_t *Bytes, size_t ByteLen,
			       MCInst *MI, uint16_t *Size, uint64_t Address,
			       void *Info)
{
	MI->MRI = (MCRegisterInfo *)Info;
	return RISCV_getInstruction(MI, Size, Bytes, ByteLen, Address, NULL) !=
	       MCDisassembler_Fail;
}
