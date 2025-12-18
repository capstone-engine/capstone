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

static const unsigned AE_DRDecoderTable[] = {
	Xtensa_AED0,  Xtensa_AED1,  Xtensa_AED2,  Xtensa_AED3,
	Xtensa_AED4,  Xtensa_AED5,  Xtensa_AED6,  Xtensa_AED7,
	Xtensa_AED8,  Xtensa_AED9,  Xtensa_AED10, Xtensa_AED11,
	Xtensa_AED12, Xtensa_AED13, Xtensa_AED14, Xtensa_AED15
};

static const unsigned AE_VALIGNDecoderTable[] = { Xtensa_U0, Xtensa_U1,
						  Xtensa_U2, Xtensa_U3 };

static DecodeStatus DecodeAE_DRRegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo >= ARR_SIZE(AE_DRDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = AE_DRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeAE_VALIGNRegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
	if (RegNo >= ARR_SIZE(AE_VALIGNDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = AE_VALIGNDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeARRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= ARR_SIZE(ARDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = ARDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned QRDecoderTable[] = { Xtensa_Q0, Xtensa_Q1, Xtensa_Q2,
					   Xtensa_Q3, Xtensa_Q4, Xtensa_Q5,
					   Xtensa_Q6, Xtensa_Q7 };

static DecodeStatus DecodeQRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= ARR_SIZE(QRDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = QRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned FPRDecoderTable[] = {
	Xtensa_F0,  Xtensa_F1,	Xtensa_F2,  Xtensa_F3, Xtensa_F4,  Xtensa_F5,
	Xtensa_F6,  Xtensa_F7,	Xtensa_F8,  Xtensa_F9, Xtensa_F10, Xtensa_F11,
	Xtensa_F12, Xtensa_F13, Xtensa_F14, Xtensa_F15
};

static DecodeStatus DecodeFPRRegisterClass(MCInst *Inst, uint64_t RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	if (RegNo >= ARR_SIZE(FPRDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = FPRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned BRDecoderTable[] = {
	Xtensa_B0,  Xtensa_B1,	Xtensa_B2,  Xtensa_B3, Xtensa_B4,  Xtensa_B5,
	Xtensa_B6,  Xtensa_B7,	Xtensa_B8,  Xtensa_B9, Xtensa_B10, Xtensa_B11,
	Xtensa_B12, Xtensa_B13, Xtensa_B14, Xtensa_B15
};

static const unsigned BR2DecoderTable[] = { Xtensa_B0_B1,   Xtensa_B2_B3,
					    Xtensa_B4_B5,   Xtensa_B6_B7,
					    Xtensa_B8_B9,   Xtensa_B10_B11,
					    Xtensa_B12_B13, Xtensa_B14_B15 };

static const unsigned BR4DecoderTable[] = { Xtensa_B0_B1_B2_B3,
					    Xtensa_B4_B5_B6_B7,
					    Xtensa_B8_B9_B10_B11,
					    Xtensa_B12_B13_B14_B15 };

static DecodeStatus DecodeXtensaRegisterClass(MCInst *Inst, uint64_t RegNo,
					      uint64_t Address,
					      const void *Decoder,
					      const unsigned *DecoderTable,
					      size_t DecoderTableLen)
{
	if (RegNo >= DecoderTableLen)
		return MCDisassembler_Fail;

	unsigned Reg = DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBR2RegisterClass(MCInst *Inst, uint64_t RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	return DecodeXtensaRegisterClass(Inst, RegNo, Address, Decoder,
					 BR2DecoderTable,
					 ARR_SIZE(BR2DecoderTable));
}

static DecodeStatus DecodeBR4RegisterClass(MCInst *Inst, uint64_t RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	return DecodeXtensaRegisterClass(Inst, RegNo, Address, Decoder,
					 BR4DecoderTable,
					 ARR_SIZE(BR4DecoderTable));
}

static DecodeStatus DecodeBRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= ARR_SIZE(BRDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = BRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned MRDecoderTable[] = { Xtensa_M0, Xtensa_M1, Xtensa_M2,
					   Xtensa_M3 };

static DecodeStatus DecodeMRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo >= ARR_SIZE(MRDecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = MRDecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned MR01DecoderTable[] = { Xtensa_M0, Xtensa_M1 };

static DecodeStatus DecodeMR01RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= ARR_SIZE(MR01DecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = MR01DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static const unsigned MR23DecoderTable[] = { Xtensa_M2, Xtensa_M3 };

static DecodeStatus DecodeMR23RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo >= ARR_SIZE(MR23DecoderTable))
		return MCDisassembler_Fail;

	unsigned Reg = MR23DecoderTable[RegNo];
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

bool Xtensa_getFeatureBits(unsigned int mode, unsigned int feature)
{
	// we support everything
	return true;
}

// Verify SR and UR
bool CheckRegister(MCInst *Inst, unsigned RegNo)
{
	unsigned NumIntLevels = 0;
	unsigned NumTimers = 0;
	unsigned NumMiscSR = 0;
	bool IsESP32 = false;
	bool IsESP32S2 = false;
	bool Res = true;

	// Assume that CPU is esp32 by default
	if ((Inst->csh->mode & CS_MODE_XTENSA_ESP32)) {
		NumIntLevels = 6;
		NumTimers = 3;
		NumMiscSR = 4;
		IsESP32 = true;
	} else if (Inst->csh->mode & CS_MODE_XTENSA_ESP32S2) {
		NumIntLevels = 6;
		NumTimers = 3;
		NumMiscSR = 4;
		IsESP32S2 = true;
	} else if (Inst->csh->mode & CS_MODE_XTENSA_ESP8266) {
		NumIntLevels = 2;
		NumTimers = 1;
	}

	switch (RegNo) {
	case Xtensa_LBEG:
	case Xtensa_LEND:
	case Xtensa_LCOUNT:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureLoop);
		break;
	case Xtensa_BREG:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureBoolean);
		break;
	case Xtensa_LITBASE:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureExtendedL32R);
		break;
	case Xtensa_SCOMPARE1:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureS32C1I);
		break;
	case Xtensa_ACCLO:
	case Xtensa_ACCHI:
	case Xtensa_M0:
	case Xtensa_M1:
	case Xtensa_M2:
	case Xtensa_M3:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureMAC16);
		break;
	case Xtensa_WINDOWBASE:
	case Xtensa_WINDOWSTART:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureWindowed);
		break;
	case Xtensa_IBREAKENABLE:
	case Xtensa_IBREAKA0:
	case Xtensa_IBREAKA1:
	case Xtensa_DBREAKA0:
	case Xtensa_DBREAKA1:
	case Xtensa_DBREAKC0:
	case Xtensa_DBREAKC1:
	case Xtensa_DEBUGCAUSE:
	case Xtensa_ICOUNT:
	case Xtensa_ICOUNTLEVEL:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureDebug);
		break;
	case Xtensa_ATOMCTL:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureATOMCTL);
		break;
	case Xtensa_MEMCTL:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureMEMCTL);
		break;
	case Xtensa_EPC1:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureException);
		break;
	case Xtensa_EPC2:
	case Xtensa_EPC3:
	case Xtensa_EPC4:
	case Xtensa_EPC5:
	case Xtensa_EPC6:
	case Xtensa_EPC7:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureHighPriInterrupts);
		Res = Res & (NumIntLevels >= (RegNo - Xtensa_EPC1));
		break;
	case Xtensa_EPS2:
	case Xtensa_EPS3:
	case Xtensa_EPS4:
	case Xtensa_EPS5:
	case Xtensa_EPS6:
	case Xtensa_EPS7:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureHighPriInterrupts);
		Res = Res & (NumIntLevels > (RegNo - Xtensa_EPS2));
		break;
	case Xtensa_EXCSAVE1:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureException);
		break;
	case Xtensa_EXCSAVE2:
	case Xtensa_EXCSAVE3:
	case Xtensa_EXCSAVE4:
	case Xtensa_EXCSAVE5:
	case Xtensa_EXCSAVE6:
	case Xtensa_EXCSAVE7:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureHighPriInterrupts);
		Res = Res & (NumIntLevels >= (RegNo - Xtensa_EXCSAVE1));
		break;
	case Xtensa_DEPC:
	case Xtensa_EXCCAUSE:
	case Xtensa_EXCVADDR:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureException);
		break;
	case Xtensa_CPENABLE:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureCoprocessor);
		break;
	case Xtensa_VECBASE:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureRelocatableVector);
		break;
	case Xtensa_CCOUNT:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureTimerInt);
		Res &= (NumTimers > 0);
		break;
	case Xtensa_CCOMPARE0:
	case Xtensa_CCOMPARE1:
	case Xtensa_CCOMPARE2:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureTimerInt);
		Res &= (NumTimers > (RegNo - Xtensa_CCOMPARE0));
		break;
	case Xtensa_PRID:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeaturePRID);
		break;
	case Xtensa_INTERRUPT:
	case Xtensa_INTCLEAR:
	case Xtensa_INTENABLE:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureInterrupt);
		break;
	case Xtensa_MISC0:
	case Xtensa_MISC1:
	case Xtensa_MISC2:
	case Xtensa_MISC3:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureMiscSR);
		Res &= (NumMiscSR > (RegNo - Xtensa_MISC0));
		break;
	case Xtensa_THREADPTR:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureTHREADPTR);
		break;
	case Xtensa_GPIO_OUT:
		Res = IsESP32S2;
		break;
	case Xtensa_EXPSTATE:
		Res = IsESP32;
		break;
	case Xtensa_FCR:
	case Xtensa_FSR:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureSingleFloat);
		break;
	case Xtensa_F64R_LO:
	case Xtensa_F64R_HI:
	case Xtensa_F64S:
		Res = Xtensa_getFeatureBits(Inst->csh->mode,
					    Xtensa_FeatureDFPAccel);
		break;
	}

	return Res;
}

static const unsigned SRDecoderTable[] = {
	Xtensa_LBEG,	    0,	 Xtensa_LEND,	      1,
	Xtensa_LCOUNT,	    2,	 Xtensa_SAR,	      3,
	Xtensa_BREG,	    4,	 Xtensa_LITBASE,      5,
	Xtensa_SCOMPARE1,   12,	 Xtensa_ACCLO,	      16,
	Xtensa_ACCHI,	    17,	 Xtensa_M0,	      32,
	Xtensa_M1,	    33,	 Xtensa_M2,	      34,
	Xtensa_M3,	    35,	 Xtensa_WINDOWBASE,   72,
	Xtensa_WINDOWSTART, 73,	 Xtensa_IBREAKENABLE, 96,
	Xtensa_MEMCTL,	    97,	 Xtensa_ATOMCTL,      99,
	Xtensa_DDR,	    104, Xtensa_IBREAKA0,     128,
	Xtensa_IBREAKA1,    129, Xtensa_DBREAKA0,     144,
	Xtensa_DBREAKA1,    145, Xtensa_DBREAKC0,     160,
	Xtensa_DBREAKC1,    161, Xtensa_CONFIGID0,    176,
	Xtensa_EPC1,	    177, Xtensa_EPC2,	      178,
	Xtensa_EPC3,	    179, Xtensa_EPC4,	      180,
	Xtensa_EPC5,	    181, Xtensa_EPC6,	      182,
	Xtensa_EPC7,	    183, Xtensa_DEPC,	      192,
	Xtensa_EPS2,	    194, Xtensa_EPS3,	      195,
	Xtensa_EPS4,	    196, Xtensa_EPS5,	      197,
	Xtensa_EPS6,	    198, Xtensa_EPS7,	      199,
	Xtensa_CONFIGID1,   208, Xtensa_EXCSAVE1,     209,
	Xtensa_EXCSAVE2,    210, Xtensa_EXCSAVE3,     211,
	Xtensa_EXCSAVE4,    212, Xtensa_EXCSAVE5,     213,
	Xtensa_EXCSAVE6,    214, Xtensa_EXCSAVE7,     215,
	Xtensa_CPENABLE,    224, Xtensa_INTERRUPT,    226,
	Xtensa_INTCLEAR,    227, Xtensa_INTENABLE,    228,
	Xtensa_PS,	    230, Xtensa_VECBASE,      231,
	Xtensa_EXCCAUSE,    232, Xtensa_DEBUGCAUSE,   233,
	Xtensa_CCOUNT,	    234, Xtensa_PRID,	      235,
	Xtensa_ICOUNT,	    236, Xtensa_ICOUNTLEVEL,  237,
	Xtensa_EXCVADDR,    238, Xtensa_CCOMPARE0,    240,
	Xtensa_CCOMPARE1,   241, Xtensa_CCOMPARE2,    242,
	Xtensa_MISC0,	    244, Xtensa_MISC1,	      245,
	Xtensa_MISC2,	    246, Xtensa_MISC3,	      247
};

static DecodeStatus DecodeSRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	//	const llvm_MCSubtargetInfo STI =
	//		((const MCDisassembler *)Decoder)->getSubtargetInfo();

	if (RegNo > 255)
		return MCDisassembler_Fail;

	for (unsigned i = 0; i < ARR_SIZE(SRDecoderTable); i += 2) {
		if (SRDecoderTable[i + 1] == RegNo) {
			unsigned Reg = SRDecoderTable[i];

			if (!CheckRegister(Inst, Reg))
				return MCDisassembler_Fail;

			MCOperand_CreateReg0(Inst, (Reg));
			return MCDisassembler_Success;
		}
	}

	return MCDisassembler_Fail;
}

static const unsigned URDecoderTable[] = {
	Xtensa_GPIO_OUT, 0,   Xtensa_EXPSTATE, 230, Xtensa_THREADPTR, 231,
	Xtensa_FCR,	 232, Xtensa_FSR,      233, Xtensa_F64R_LO,   234,
	Xtensa_F64R_HI,	 235, Xtensa_F64S,     236
};

static DecodeStatus DecodeURRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address, const void *Decoder)
{
	if (RegNo > 255)
		return MCDisassembler_Fail;

	for (unsigned i = 0; i < ARR_SIZE(URDecoderTable); i += 2) {
		if (URDecoderTable[i + 1] == RegNo) {
			unsigned Reg = URDecoderTable[i];

			if (!CheckRegister(Inst, Reg))
				return MCDisassembler_Fail;

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
	return false;
}

static DecodeStatus decodeCallOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(18, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm << 2), 20)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeJumpOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(18, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
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
		CS_ASSERT_RET_VAL(isUIntN(12, Imm) && "Invalid immediate",
				  MCDisassembler_Fail);
		if (!tryAddingSymbolicOperand(
			    SignExtend64((Imm), 12) + 4 + Address, true,
			    Address, 0, 3, Inst, Decoder))
			MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 12)));
		break;
	default:
		CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
				  MCDisassembler_Fail);
		if (!tryAddingSymbolicOperand(
			    SignExtend64((Imm), 8) + 4 + Address, true, Address,
			    0, 3, Inst, Decoder))
			MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 8)));
	}
	return MCDisassembler_Success;
}

static DecodeStatus decodeLoopOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if (!tryAddingSymbolicOperand(Imm + 4 + Address, true, Address, 0, 3,
				      Inst, Decoder))
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeL32ROperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(16, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, OneExtend64(Imm << 2, 18));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm8Operand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 8)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm8_sh8Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(16, Imm) && ((Imm & 0xff) == 0) &&
				  "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 16)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm12Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(12, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (SignExtend64((Imm), 12)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeUimm4Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeUimm5Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(5, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm1_16Operand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm + 1));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm1n_15Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if (!Imm)
		MCOperand_CreateImm0(Inst, (-1));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm32n_95Operand(MCInst *Inst, uint64_t Imm,
					   int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(7, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0x60) == 0x60)
		MCOperand_CreateImm0(Inst, ((~0x1f) | Imm));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm8n_7Operand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if (Imm > 7)
		MCOperand_CreateImm0(Inst, (Imm - 16));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeImm64n_4nOperand(MCInst *Inst, uint64_t Imm,
					   int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(6, Imm) && ((Imm & 0x3) == 0) &&
				  "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, ((~0x3f) | (Imm)));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset8m32Operand(MCInst *Inst, uint64_t Imm,
					    int64_t Address,
					    const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(10, Imm) && ((Imm & 0x3) == 0) &&
				  "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeEntry_Imm12OpValue(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(15, Imm) && ((Imm & 0x7) == 0) &&
				  "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeShimm1_31Operand(MCInst *Inst, uint64_t Imm,
					   int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(5, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (32 - Imm));
	return MCDisassembler_Success;
}

//static DecodeStatus decodeShimm0_31Operand(MCInst *Inst, uint64_t Imm,
//					   int64_t Address, const void *Decoder)
//{
//	CS_ASSERT_RET_VAL(isUIntN(5, Imm) && "Invalid immediate", MCDisassembler_Fail);
//	MCOperand_CreateImm0(Inst, (32 - Imm));
//	return MCDisassembler_Success;
//}

static DecodeStatus decodeImm7_22Operand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm + 7));
	return MCDisassembler_Success;
}

static DecodeStatus decodeSelect_2Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeSelect_4Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeSelect_8Operand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeSelect_16Operand(MCInst *Inst, uint64_t Imm,
					   int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeSelect_256Operand(MCInst *Inst, uint64_t Imm,
					    int64_t Address,
					    const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_16_16Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isIntN(Imm, 8) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0xf) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 4));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_256_8Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isIntN(16, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0x7) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 3));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_256_16Operand(MCInst *Inst, uint64_t Imm,
					       int64_t Address,
					       const void *Decoder)
{
	CS_ASSERT_RET_VAL(isIntN(16, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0xf) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 4));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_256_4Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isIntN(16, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0x2) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 2));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_128_2Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0x1) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 1));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_128_1Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static DecodeStatus decodeOffset_64_16Operand(MCInst *Inst, uint64_t Imm,
					      int64_t Address,
					      const void *Decoder)
{
	CS_ASSERT_RET_VAL(isIntN(16, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	if ((Imm & 0xf) != 0)
		MCOperand_CreateImm0(Inst, (Imm << 4));
	else
		MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

static int64_t TableB4const[16] = { -1, 1,  2,	3,  4,	5,  6,	 7,
				    8,	10, 12, 16, 32, 64, 128, 256 };
static DecodeStatus decodeB4constOperand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);

	MCOperand_CreateImm0(Inst, (TableB4const[Imm]));
	return MCDisassembler_Success;
}

static int64_t TableB4constu[16] = { 32768, 65536, 2,  3,  4,  5,  6,	7,
				     8,	    10,	   12, 16, 32, 64, 128, 256 };
static DecodeStatus decodeB4constuOperand(MCInst *Inst, uint64_t Imm,
					  int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(4, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);

	MCOperand_CreateImm0(Inst, (TableB4constu[Imm]));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem8Operand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(12, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 4) & 0xff));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem16Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(12, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 3) & 0x1fe));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem32Operand(MCInst *Inst, uint64_t Imm,
				       int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(12, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 2) & 0x3fc));
	return MCDisassembler_Success;
}

static DecodeStatus decodeMem32nOperand(MCInst *Inst, uint64_t Imm,
					int64_t Address, const void *Decoder)
{
	CS_ASSERT_RET_VAL(isUIntN(8, Imm) && "Invalid immediate",
			  MCDisassembler_Fail);
	DecodeARRegisterClass(Inst, Imm & 0xf, Address, Decoder);
	MCOperand_CreateImm0(Inst, ((Imm >> 2) & 0x3c));
	return MCDisassembler_Success;
}

/// Read two bytes from the ArrayRef and return 16 bit data sorted
/// according to the given endianness.
static DecodeStatus readInstruction16(MCInst *MI, const uint8_t *Bytes,
				      size_t BytesLen, uint64_t Address,
				      uint64_t *Size, uint64_t *Insn,
				      bool IsLittleEndian)
{
	// We want to read exactly 2 Bytes of data.
	if (BytesLen < 2) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	*Insn = readBytes16(MI, Bytes);
	*Size = 2;

	return MCDisassembler_Success;
}

/// Read three bytes from the ArrayRef and return 24 bit data
static DecodeStatus readInstruction24(MCInst *MI, const uint8_t *Bytes,
				      size_t BytesLen, uint64_t Address,
				      uint64_t *Size, uint64_t *Insn,
				      bool IsLittleEndian, bool CheckTIE)
{
	// We want to read exactly 3 Bytes of data.
	if (BytesLen < 3) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	if (CheckTIE && (Bytes[0] & 0x8) != 0)
		return MCDisassembler_Fail;
	*Insn = readBytes24(MI, Bytes);
	*Size = 3;

	return MCDisassembler_Success;
}

/// Read three bytes from the ArrayRef and return 32 bit data
static DecodeStatus readInstruction32(MCInst *MI, const uint8_t *Bytes,
				      size_t BytesLen, uint64_t Address,
				      uint64_t *Size, uint64_t *Insn,
				      bool IsLittleEndian)
{
	// We want to read exactly 4 Bytes of data.
	if (BytesLen < 4) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	if ((Bytes[0] & 0x8) == 0)
		return MCDisassembler_Fail;
	*Insn = readBytes32(MI, Bytes);
	*Size = 4;

	return MCDisassembler_Success;
}

/// Read InstSize bytes from the ArrayRef and return 24 bit data
static DecodeStatus readInstructionN(const uint8_t *Bytes, size_t BytesLen,
				     uint64_t Address, unsigned InstSize,
				     uint64_t *Size, uint64_t *Insn,
				     bool IsLittleEndian)
{
	// We want to read exactly 3 Bytes of data.
	if (BytesLen < InstSize) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	*Insn = 0;
	for (unsigned i = 0; i < InstSize; i++)
		*Insn |= (uint64_t)(Bytes[i]) << (8 * i);

	*Size = InstSize;
	return MCDisassembler_Success;
}

#include "XtensaGenDisassemblerTables.inc"

FieldFromInstruction(fieldFromInstruction_2, uint64_t);
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint64_t);
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2,
		  uint64_t);

FieldFromInstruction(fieldFromInstruction_4, uint64_t);
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint64_t);
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4,
		  uint64_t);

FieldFromInstruction(fieldFromInstruction_6, uint64_t);
DecodeToMCInst(decodeToMCInst_6, fieldFromInstruction_6, uint64_t);
DecodeInstruction(decodeInstruction_6, fieldFromInstruction_6, decodeToMCInst_6,
		  uint64_t);

static bool hasDensity()
{
	return true;
}
static bool hasESP32S3Ops()
{
	return true;
}
static bool hasHIFI3()
{
	return true;
}

static DecodeStatus getInstruction(MCInst *MI, uint64_t *Size,
				   const uint8_t *Bytes, size_t BytesLen,
				   uint64_t Address)
{
	uint64_t Insn;
	DecodeStatus Result;
	bool IsLittleEndian = MI->csh->mode & CS_MODE_LITTLE_ENDIAN;

	// Parse 16-bit instructions
	if (hasDensity()) {
		Result = readInstruction16(MI, Bytes, BytesLen, Address, Size,
					   &Insn, IsLittleEndian);
		if (Result == MCDisassembler_Fail)
			return MCDisassembler_Fail;

		Result = decodeInstruction_2(DecoderTable16, MI, Insn, Address,
					     NULL);
		if (Result != MCDisassembler_Fail) {
			*Size = 2;
			return Result;
		}
	}

	// Parse Core 24-bit instructions
	Result = readInstruction24(MI, Bytes, BytesLen, Address, Size, &Insn,
				   IsLittleEndian, false);
	if (Result == MCDisassembler_Fail)
		return MCDisassembler_Fail;

	Result = decodeInstruction_3(DecoderTable24, MI, Insn, Address, NULL);
	if (Result != MCDisassembler_Fail) {
		*Size = 3;
		return Result;
	}

	if (hasESP32S3Ops()) {
		// Parse ESP32S3 24-bit instructions
		Result = readInstruction24(MI, Bytes, BytesLen, Address, Size,
					   &Insn, IsLittleEndian, true);
		if (Result != MCDisassembler_Fail) {
			Result = decodeInstruction_3(DecoderTableESP32S324, MI,
						     Insn, Address, NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 3;
				return Result;
			}
		}

		// Parse ESP32S3 32-bit instructions
		Result = readInstruction32(MI, Bytes, BytesLen, Address, Size,
					   &Insn, IsLittleEndian);
		if (Result == MCDisassembler_Fail)
			return MCDisassembler_Fail;

		Result = decodeInstruction_4(DecoderTableESP32S332, MI, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail) {
			*Size = 4;
			return Result;
		}
	}

	if (hasHIFI3()) {
		Result = decodeInstruction_3(DecoderTableHIFI324, MI, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;

		Result = readInstructionN(Bytes, BytesLen, Address, 48, Size,
					  &Insn, IsLittleEndian);
		if (Result == MCDisassembler_Fail)
			return MCDisassembler_Fail;

		Result = decodeInstruction_6(DecoderTableHIFI348, MI, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}
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
