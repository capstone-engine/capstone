//===-- ARMDisassembler.cpp - Disassembler for ARM/Thumb ISA --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_ARM

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "ARMAddressingModes.h"
#include "ARMBaseInfo.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "../../LEB128.h"
#include "../../MCDisassembler.h"
#include "../../cs_priv.h"
#include "../../utils.h"

#include "ARMDisassembler.h"
#include "ARMMapping.h"

#define GET_SUBTARGETINFO_ENUM
#include "ARMGenSubtargetInfo.inc"

#define GET_INSTRINFO_MC_DESC
#include "ARMGenInstrInfo.inc"

#define GET_INSTRINFO_ENUM
#include "ARMGenInstrInfo.inc"

static bool ITStatus_push_back(ARM_ITStatus *it, char v)
{
	if (it->size >= sizeof(it->ITStates)) {
		// TODO: consider warning user.
		it->size = 0;
	}
	it->ITStates[it->size] = v;
	it->size++;

	return true;
}

// Returns true if the current instruction is in an IT block
static bool ITStatus_instrInITBlock(ARM_ITStatus *it)
{
	//return !ITStates.empty();
	return (it->size > 0);
}

// Returns true if current instruction is the last instruction in an IT block
static bool ITStatus_instrLastInITBlock(ARM_ITStatus *it)
{
	return (it->size == 1);
}

// Handles the condition code status of instructions in IT blocks

// Returns the condition code for instruction in IT block
static unsigned ITStatus_getITCC(ARM_ITStatus *it)
{
	unsigned CC = ARMCC_AL;

	if (ITStatus_instrInITBlock(it))
		//CC = ITStates.back();
		CC = it->ITStates[it->size-1];

	return CC;
}

// Advances the IT block state to the next T or E
static void ITStatus_advanceITState(ARM_ITStatus *it)
{
	//ITStates.pop_back();
	it->size--;
}

// Called when decoding an IT instruction. Sets the IT state for the following
// instructions that for the IT block. Firstcond and Mask correspond to the 
// fields in the IT instruction encoding.
static void ITStatus_setITState(ARM_ITStatus *it, char Firstcond, char Mask)
{
	// (3 - the number of trailing zeros) is the number of then / else.
	unsigned CondBit0 = Firstcond & 1;
	unsigned NumTZ = CountTrailingZeros_32(Mask);
	unsigned char CCBits = (unsigned char)Firstcond & 0xf;
	unsigned Pos;

	//assert(NumTZ <= 3 && "Invalid IT mask!");
	// push condition codes onto the stack the correct order for the pops
	for (Pos = NumTZ + 1; Pos <= 3; ++Pos) {
		bool T = ((Mask >> Pos) & 1) == (int)CondBit0;

		if (T)
			ITStatus_push_back(it, CCBits);
		else
			ITStatus_push_back(it, CCBits ^ 1);
	}

	ITStatus_push_back(it, CCBits);
}

/// ThumbDisassembler - Thumb disassembler for all Thumb platforms.

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
		default:	// never reached
			return false;
	}
}

#include "CapstoneARMModule.h"

// Hacky: enable all features for disassembler
bool ARM_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if ((mode & CS_MODE_V8) == 0) {
		// not V8 mode
		if (feature == ARM_HasV8Ops || feature == ARM_HasV8_1aOps ||
			feature == ARM_HasV8_4aOps || feature == ARM_HasV8_3aOps)
			// HasV8MBaselineOps
			return false;
	} else {
		if (feature == ARM_FeatureVFPOnlySP)
			return false;
	}

	if ((mode & CS_MODE_MCLASS) == 0) {
		if (feature == ARM_FeatureMClass)
			return false;
	}

	if ((mode & CS_MODE_THUMB) == 0) {
		// not Thumb
		if (feature == ARM_FeatureThumb2 || feature == ARM_ModeThumb)
			return false;
		// FIXME: what mode enables D16?
		if (feature == ARM_FeatureD16)
			return false;
	} else {
		// Thumb
		if (feature == ARM_FeatureD16)
			return false;
	}

	if (feature == ARM_FeatureMClass && (mode & CS_MODE_MCLASS) == 0)
		return false;

	// we support everything
	return true;
}

static DecodeStatus DecodePredicateOperand(MCInst *Inst, unsigned Val,
		uint64_t Address, const void *Decoder)
{
	if (Val == 0xF) return MCDisassembler_Fail;

	// AL predicate is not allowed on Thumb1 branches.
	if (MCInst_getOpcode(Inst) == ARM_tBcc && Val == 0xE)
		return MCDisassembler_Fail;

	MCOperand_CreateImm0(Inst, Val);

	if (Val == ARMCC_AL) {
		MCOperand_CreateReg0(Inst, 0);
	} else
		MCOperand_CreateReg0(Inst, ARM_CPSR);

	return MCDisassembler_Success;
}

#define GET_REGINFO_MC_DESC
#include "ARMGenRegisterInfo.inc"
void ARM_init(MCRegisterInfo *MRI)
{
	/* 
		InitMCRegisterInfo(ARMRegDesc, 289,
		RA, PC,
		ARMMCRegisterClasses, 103,
		ARMRegUnitRoots, 77, ARMRegDiffLists, ARMRegStrings,
		ARMSubRegIdxLists, 57,
		ARMSubRegIdxRanges, ARMRegEncodingTable);
	 */

	MCRegisterInfo_InitMCRegisterInfo(MRI, ARMRegDesc, 289,
			0, 0, 
			ARMMCRegisterClasses, 103,
			0, 0, ARMRegDiffLists, 0, 
			ARMSubRegIdxLists, 57,
			0);
}

// Post-decoding checks
static DecodeStatus checkDecodedInstruction(MCInst *MI,
		uint32_t Insn,
		DecodeStatus Result)
{
	switch (MCInst_getOpcode(MI)) {
		case ARM_HVC: {
			  // HVC is undefined if condition = 0xf otherwise upredictable
			  // if condition != 0xe
			  uint32_t Cond = (Insn >> 28) & 0xF;

			  if (Cond == 0xF)
				  return MCDisassembler_Fail;

			  if (Cond != 0xE)
				  return MCDisassembler_SoftFail;

			  return Result;
		  }
		default:
			   return Result;
	}
}

static DecodeStatus _ARM_getInstruction(cs_struct *ud, MCInst *MI, const uint8_t *code, size_t code_len,
		uint16_t *Size, uint64_t Address)
{
	uint32_t insn;
	DecodeStatus result;

	*Size = 0;

	if (code_len < 4)
		// not enough data
		return MCDisassembler_Fail;

	if (MI->flat_insn->detail) {
		unsigned int i;

		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, arm) + sizeof(cs_arm));

		for (i = 0; i < ARR_SIZE(MI->flat_insn->detail->arm.operands); i++) {
			MI->flat_insn->detail->arm.operands[i].vector_index = -1;
			MI->flat_insn->detail->arm.operands[i].neon_lane = -1;
		}
	}

	if (MODE_IS_BIG_ENDIAN(ud->mode))
		insn = (code[3] << 0) | (code[2] << 8) |
			(code[1] <<  16) | ((uint32_t) code[0] << 24);
	else
		insn = ((uint32_t) code[3] << 24) | (code[2] << 16) |
			(code[1] <<  8) | (code[0] <<  0);

	// Calling the auto-generated decoder function.
	result =
	    decodeInstruction_4(DecoderTableARM32, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		result = checkDecodedInstruction(MI, insn, result);
		if (result != MCDisassembler_Fail)
			*Size = 4;

		return result;
	}

	// VFP and NEON instructions, similarly, are shared between ARM
	// and Thumb modes.
	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTableVFP32, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTableVFPV832, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_4(DecoderTableNEONData32, MI, insn, Address,
				     0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		// Add a fake predicate operand, because we share these instruction
		// definitions with Thumb2 where these instructions are predicable.
		if (!DecodePredicateOperand(MI, 0xE, Address, NULL))
			return MCDisassembler_Fail;
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_4(DecoderTableNEONLoadStore32, MI, insn,
				     Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		// Add a fake predicate operand, because we share these instruction
		// definitions with Thumb2 where these instructions are predicable.
		if (!DecodePredicateOperand(MI, 0xE, Address, NULL))
			return MCDisassembler_Fail;
		return result;
	}

	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTableNEONDup32, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		// Add a fake predicate operand, because we share these instruction
		// definitions with Thumb2 where these instructions are predicable.
		if (!DecodePredicateOperand(MI, 0xE, Address, NULL))
			return MCDisassembler_Fail;
		return result;
	}

	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTablev8NEON32, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_4(DecoderTablev8Crypto32, MI, insn, Address,
				     0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	result =
	    decodeInstruction_4(DecoderTableCoProc32, MI, insn, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		result = checkDecodedInstruction(MI, insn, result);
		if (result != MCDisassembler_Fail)
			*Size = 4;

		return result;
	}

	MCInst_clear(MI);
	*Size = 0;
	return MCDisassembler_Fail;
}

// Thumb1 instructions don't have explicit S bits. Rather, they
// implicitly set CPSR. Since it's not represented in the encoding, the
// auto-generated decoder won't inject the CPSR operand. We need to fix
// that as a post-pass.
static void AddThumb1SBit(MCInst *MI, bool InITBlock)
{
	const MCOperandInfo *OpInfo = ARMInsts[MCInst_getOpcode(MI)].OpInfo;
	unsigned short NumOps = ARMInsts[MCInst_getOpcode(MI)].NumOperands;
	unsigned i;

	for (i = 0; i < NumOps; ++i) {
		if (i == MCInst_getNumOperands(MI)) break;

		if (MCOperandInfo_isOptionalDef(&OpInfo[i]) && OpInfo[i].RegClass == ARM_CCRRegClassID) {
			if (i > 0 && MCOperandInfo_isPredicate(&OpInfo[i - 1])) continue;
			MCInst_insert0(MI, i, MCOperand_CreateReg1(MI, InITBlock ? 0 : ARM_CPSR));
			return;
		}
	}

	//MI.insert(I, MCOperand_CreateReg0(Inst, InITBlock ? 0 : ARM_CPSR));
	MCInst_insert0(MI, i, MCOperand_CreateReg1(MI, InITBlock ? 0 : ARM_CPSR));
}

// Most Thumb instructions don't have explicit predicates in the
// encoding, but rather get their predicates from IT context. We need
// to fix up the predicate operands using this context information as a
// post-pass.
static DecodeStatus AddThumbPredicate(cs_struct *ud, MCInst *MI)
{
	DecodeStatus S = MCDisassembler_Success;
	const MCOperandInfo *OpInfo;
	unsigned short NumOps;
	unsigned int i;
	unsigned CC;

	// A few instructions actually have predicates encoded in them. Don't
	// try to overwrite it if we're seeing one of those.
	switch (MCInst_getOpcode(MI)) {
		case ARM_tBcc:
		case ARM_t2Bcc:
		case ARM_tCBZ:
		case ARM_tCBNZ:
		case ARM_tCPS:
		case ARM_t2CPS3p:
		case ARM_t2CPS2p:
		case ARM_t2CPS1p:
		case ARM_tMOVSr:
		case ARM_tSETEND:
			// Some instructions (mostly conditional branches) are not
			// allowed in IT blocks.
			if (ITStatus_instrInITBlock(&(ud->ITBlock)))
				S = MCDisassembler_SoftFail;
			else
				return MCDisassembler_Success;
			break;

		case ARM_t2HINT:
			if (MCOperand_getImm(MCInst_getOperand(MI, 0)) == 0x10)
				S = MCDisassembler_SoftFail;
			break;

		case ARM_tB:
		case ARM_t2B:
		case ARM_t2TBB:
		case ARM_t2TBH:
			// Some instructions (mostly unconditional branches) can
			// only appears at the end of, or outside of, an IT.
			// if (ITBlock.instrInITBlock() && !ITBlock.instrLastInITBlock())
			if (ITStatus_instrInITBlock(&(ud->ITBlock)) && !ITStatus_instrLastInITBlock(&(ud->ITBlock)))
				S = MCDisassembler_SoftFail;
			break;
		default:
			break;
	}

	// If we're in an IT block, base the predicate on that.  Otherwise,
	// assume a predicate of AL.
	CC = ITStatus_getITCC(&(ud->ITBlock));
	if (CC == 0xF) 
		CC = ARMCC_AL;

	if (ITStatus_instrInITBlock(&(ud->ITBlock)))
		ITStatus_advanceITState(&(ud->ITBlock));

	OpInfo = ARMInsts[MCInst_getOpcode(MI)].OpInfo;
	NumOps = ARMInsts[MCInst_getOpcode(MI)].NumOperands;

	for (i = 0; i < NumOps; ++i) {
		if (i == MCInst_getNumOperands(MI)) break;

		if (MCOperandInfo_isPredicate(&OpInfo[i])) {
			MCInst_insert0(MI, i, MCOperand_CreateImm1(MI, CC));

			if (CC == ARMCC_AL)
				MCInst_insert0(MI, i+1, MCOperand_CreateReg1(MI, 0));
			else
				MCInst_insert0(MI, i+1, MCOperand_CreateReg1(MI, ARM_CPSR));

			return S;
		}
	}

	MCInst_insert0(MI, i, MCOperand_CreateImm1(MI, CC));

	if (CC == ARMCC_AL)
		MCInst_insert0(MI, i + 1, MCOperand_CreateReg1(MI, 0));
	else
		MCInst_insert0(MI, i + 1, MCOperand_CreateReg1(MI, ARM_CPSR));

	return S;
}

// Thumb VFP instructions are a special case. Because we share their
// encodings between ARM and Thumb modes, and they are predicable in ARM
// mode, the auto-generated decoder will give them an (incorrect)
// predicate operand. We need to rewrite these operands based on the IT
// context as a post-pass.
static void UpdateThumbVFPPredicate(cs_struct *ud, MCInst *MI)
{
	unsigned CC;
	unsigned short NumOps;
	const MCOperandInfo *OpInfo;
	unsigned i;

	CC = ITStatus_getITCC(&(ud->ITBlock));
	if (ITStatus_instrInITBlock(&(ud->ITBlock)))
		ITStatus_advanceITState(&(ud->ITBlock));

	OpInfo = ARMInsts[MCInst_getOpcode(MI)].OpInfo;
	NumOps = ARMInsts[MCInst_getOpcode(MI)].NumOperands;

	for (i = 0; i < NumOps; ++i) {
		if (MCOperandInfo_isPredicate(&OpInfo[i])) {
			MCOperand_setImm(MCInst_getOperand(MI, i), CC);

			if (CC == ARMCC_AL)
				MCOperand_setReg(MCInst_getOperand(MI, i + 1), 0);
			else
				MCOperand_setReg(MCInst_getOperand(MI, i + 1), ARM_CPSR);

			return;
		}
	}
}

static DecodeStatus _Thumb_getInstruction(cs_struct *ud, MCInst *MI, const uint8_t *code, size_t code_len,
		uint16_t *Size, uint64_t Address)
{
	uint16_t insn16;
	DecodeStatus result;
	bool InITBlock;
	unsigned Firstcond, Mask; 
	uint32_t NEONLdStInsn, insn32, NEONDataInsn, NEONCryptoInsn, NEONv8Insn;
	size_t i;

	// We want to read exactly 2 bytes of data.
	if (code_len < 2)
		// not enough data
		return MCDisassembler_Fail;

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, arm)+sizeof(cs_arm));
		for (i = 0; i < ARR_SIZE(MI->flat_insn->detail->arm.operands); i++) {
			MI->flat_insn->detail->arm.operands[i].vector_index = -1;
			MI->flat_insn->detail->arm.operands[i].neon_lane = -1;
		}
	}

	if (MODE_IS_BIG_ENDIAN(ud->mode))
		insn16 = (code[0] << 8) | code[1];
	else
		insn16 = (code[1] << 8) | code[0];

	result =
	    decodeInstruction_2(DecoderTableThumb16, MI, insn16, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 2;
		Check(&result, AddThumbPredicate(ud, MI));
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_2(DecoderTableThumbSBit16, MI, insn16,
				     Address, 0, 0);
	if (result) {
		*Size = 2;
		InITBlock = ITStatus_instrInITBlock(&(ud->ITBlock));
		Check(&result, AddThumbPredicate(ud, MI));
		AddThumb1SBit(MI, InITBlock);
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_2(DecoderTableThumb216, MI, insn16, Address,
				     0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 2;

		// Nested IT blocks are UNPREDICTABLE.  Must be checked before we add
		// the Thumb predicate.
		if (MCInst_getOpcode(MI) == ARM_t2IT && ITStatus_instrInITBlock(&(ud->ITBlock)))
			return MCDisassembler_SoftFail;

		Check(&result, AddThumbPredicate(ud, MI));

		// If we find an IT instruction, we need to parse its condition
		// code and mask operands so that we can apply them correctly
		// to the subsequent instructions.
		if (MCInst_getOpcode(MI) == ARM_t2IT) {
			Firstcond = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, 0));
			Mask = (unsigned int)MCOperand_getImm(MCInst_getOperand(MI, 1));
			ITStatus_setITState(&(ud->ITBlock), (char)Firstcond, (char)Mask);

			// An IT instruction that would give a 'NV' predicate is unpredictable.
			// if (Firstcond == ARMCC_AL && !isPowerOf2_32(Mask))
			// 	CS << "unpredictable IT predicate sequence";
		}

		return result;
	}

	// We want to read exactly 4 bytes of data.
	if (code_len < 4)
		// not enough data
		return MCDisassembler_Fail;

	if (MODE_IS_BIG_ENDIAN(ud->mode))
		insn32 = (code[3] <<  0) | (code[2] <<  8) |
			(code[1] << 16) | ((uint32_t) code[0] << 24);
	else
		insn32 = (code[3] <<  8) | (code[2] <<  0) |
			((uint32_t) code[1] << 24) | (code[0] << 16);

	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTableThumb32, MI, insn32, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		InITBlock = ITStatus_instrInITBlock(&(ud->ITBlock));
		Check(&result, AddThumbPredicate(ud, MI));
		AddThumb1SBit(MI, InITBlock);

		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_4(DecoderTableThumb232, MI, insn32, Address,
				     0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		Check(&result, AddThumbPredicate(ud, MI));
		return result;
	}

	if (fieldFromInstruction_4(insn32, 28, 4) == 0xE) {
		MCInst_clear(MI);
		result = decodeInstruction_4(DecoderTableVFP32, MI, insn32,
					     Address, 0, 0);
		if (result != MCDisassembler_Fail) {
			*Size = 4;
			UpdateThumbVFPPredicate(ud, MI);
			return result;
		}
	}

	MCInst_clear(MI);
	result =
	    decodeInstruction_4(DecoderTableVFPV832, MI, insn32, Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	if (fieldFromInstruction_4(insn32, 28, 4) == 0xE) {
		MCInst_clear(MI);
		result = decodeInstruction_4(DecoderTableNEONDup32, MI, insn32,
					     Address, 0, 0);
		if (result != MCDisassembler_Fail) {
			*Size = 4;
			Check(&result, AddThumbPredicate(ud, MI));
			return result;
		}
	}

	if (fieldFromInstruction_4(insn32, 24, 8) == 0xF9) {
		MCInst_clear(MI);
		NEONLdStInsn = insn32;
		NEONLdStInsn &= 0xF0FFFFFF;
		NEONLdStInsn |= 0x04000000;
		result = decodeInstruction_4(DecoderTableNEONLoadStore32, MI,
					     NEONLdStInsn, Address, 0, 0);
		if (result != MCDisassembler_Fail) {
			*Size = 4;
			Check(&result, AddThumbPredicate(ud, MI));
			return result;
		}
	}

	if (fieldFromInstruction_4(insn32, 24, 4) == 0xF) {
		MCInst_clear(MI);
		NEONDataInsn = insn32;
		NEONDataInsn &= 0xF0FFFFFF; // Clear bits 27-24
		NEONDataInsn |= (NEONDataInsn & 0x10000000) >> 4; // Move bit 28 to bit 24
		NEONDataInsn |= 0x12000000; // Set bits 28 and 25
		result = decodeInstruction_4(DecoderTableNEONData32, MI,
					     NEONDataInsn, Address, 0, 0);
		if (result != MCDisassembler_Fail) {
			*Size = 4;
			Check(&result, AddThumbPredicate(ud, MI));
			return result;
		}
	}

	MCInst_clear(MI);
	NEONCryptoInsn = insn32;
	NEONCryptoInsn &= 0xF0FFFFFF; // Clear bits 27-24
	NEONCryptoInsn |= (NEONCryptoInsn & 0x10000000) >> 4; // Move bit 28 to bit 24
	NEONCryptoInsn |= 0x12000000; // Set bits 28 and 25
	result = decodeInstruction_4(DecoderTablev8Crypto32, MI, NEONCryptoInsn,
				     Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	NEONv8Insn = insn32;
	NEONv8Insn &= 0xF3FFFFFF; // Clear bits 27-26
	result = decodeInstruction_4(DecoderTablev8NEON32, MI, NEONv8Insn,
				     Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		return result;
	}

	MCInst_clear(MI);
	result = decodeInstruction_4(DecoderTableThumb2CoProc32, MI, insn32,
				     Address, 0, 0);
	if (result != MCDisassembler_Fail) {
		*Size = 4;
		Check(&result, AddThumbPredicate(ud, MI));
		return result;
	}

	MCInst_clear(MI);
	*Size = 0;

	return MCDisassembler_Fail;
}

bool Thumb_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr,
		uint16_t *size, uint64_t address, void *info)
{
	DecodeStatus status = _Thumb_getInstruction((cs_struct *)ud, instr, code, code_len, size, address);

	// TODO: fix table gen to eliminate these special cases
	if (instr->Opcode == ARM_t__brkdiv0)
		return false;

	//return status == MCDisassembler_Success;
	return status != MCDisassembler_Fail;
}

bool ARM_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr,
		uint16_t *size, uint64_t address, void *info)
{
	DecodeStatus status = _ARM_getInstruction((cs_struct *)ud, instr, code, code_len, size, address);

	//return status == MCDisassembler_Success;
	return status != MCDisassembler_Fail;
}

#endif
