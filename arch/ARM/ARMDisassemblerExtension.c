/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#include "ARMDisassemblerExtension.h"
#include "ARMBaseInfo.h"

bool ITBlock_push_back(ARM_ITBlock *it, char v)
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
bool ITBlock_instrInITBlock(ARM_ITBlock *it)
{
	return (it->size > 0);
}

// Returns true if current instruction is the last instruction in an IT block
bool ITBlock_instrLastInITBlock(ARM_ITBlock *it)
{
	return (it->size == 1);
}

// Returns the condition code for instruction in IT block
unsigned ITBlock_getITCC(ARM_ITBlock *it)
{
	unsigned CC = ARMCC_AL;

	if (ITBlock_instrInITBlock(it))
		CC = it->ITStates[it->size - 1];

	return CC;
}

// Advances the IT block state to the next T or E
void ITBlock_advanceITState(ARM_ITBlock *it)
{
	it->size--;
}

// Called when decoding an IT instruction. Sets the IT state for the following
// instructions that for the IT block. Firstcond and Mask correspond to the
// fields in the IT instruction encoding.
void ITBlock_setITState(ARM_ITBlock *it, char Firstcond, char Mask)
{
	// (3 - the number of trailing zeros) is the number of then / else.
	unsigned NumTZ = CountTrailingZeros_8(Mask);
	unsigned char CCBits = (unsigned char)(Firstcond & 0xf);
	CS_ASSERT_RET(NumTZ <= 3 && "Invalid IT mask!");
	// push condition codes onto the stack the correct order for the pops
	for (unsigned Pos = NumTZ + 1; Pos <= 3; ++Pos) {
		unsigned Else = (Mask >> Pos) & 1;
		ITBlock_push_back(it, CCBits ^ Else);
	}
	ITBlock_push_back(it, CCBits);
}

bool VPTBlock_push_back(ARM_VPTBlock *it, char v)
{
	if (it->size >= sizeof(it->VPTStates)) {
		// TODO: consider warning user.
		it->size = 0;
	}
	it->VPTStates[it->size] = v;
	it->size++;

	return true;
}

bool VPTBlock_instrInVPTBlock(ARM_VPTBlock *VPT)
{
	return VPT->size > 0;
}

unsigned VPTBlock_getVPTPred(ARM_VPTBlock *VPT)
{
	unsigned Pred = ARMVCC_None;
	if (VPTBlock_instrInVPTBlock(VPT))
		Pred = VPT->VPTStates[VPT->size - 1];
	return Pred;
}

void VPTBlock_advanceVPTState(ARM_VPTBlock *VPT)
{
	VPT->size--;
}

void VPTBlock_setVPTState(ARM_VPTBlock *VPT, char Mask)
{
	// (3 - the number of trailing zeros) is the number of then / else.
	unsigned NumTZ = CountTrailingZeros_8(Mask);
	CS_ASSERT_RET(NumTZ <= 3 && "Invalid VPT mask!");
	// push predicates onto the stack the correct order for the pops
	for (unsigned Pos = NumTZ + 1; Pos <= 3; ++Pos) {
		bool T = ((Mask >> Pos) & 1) == 0;
		if (T)
			VPTBlock_push_back(VPT, ARMVCC_Then);
		else
			VPTBlock_push_back(VPT, ARMVCC_Else);
	}
	VPTBlock_push_back(VPT, ARMVCC_Then);
}

// Imported from ARMBaseInstrInfo.h
//
/// isValidCoprocessorNumber - decide whether an explicit coprocessor
/// number is legal in generic instructions like CDP. The answer can
/// vary with the subtarget.
bool isValidCoprocessorNumber(MCInst *Inst, unsigned Num)
{
	// In Armv7 and Armv8-M CP10 and CP11 clash with VFP/NEON, however, the
	// coprocessor is still valid for CDP/MCR/MRC and friends. Allowing it is
	// useful for code which is shared with older architectures which do not
	// know the new VFP/NEON mnemonics.

	// Armv8-A disallows everything *other* than 111x (CP14 and CP15).
	if (ARM_getFeatureBits(Inst->csh->mode, ARM_HasV8Ops) &&
	    (Num & 0xE) != 0xE)
		return false;

	// Armv8.1-M disallows 100x (CP8,CP9) and 111x (CP14,CP15)
	// which clash with MVE.
	if (ARM_getFeatureBits(Inst->csh->mode, ARM_HasV8_1MMainlineOps) &&
	    ((Num & 0xE) == 0x8 || (Num & 0xE) == 0xE))
		return false;

	return true;
}

// Imported from ARMMCTargetDesc.h
bool ARM_isVpred(arm_op_type op)
{
	return op == ARM_OP_VPRED_R || op == ARM_OP_VPRED_N;
}

// Imported from ARMBaseInstrInfo.h
//
// This table shows the VPT instruction variants, i.e. the different
// mask field encodings, see also B5.6. Predication/conditional execution in
// the ArmARM.
bool isVPTOpcode(int Opc)
{
	return Opc == ARM_MVE_VPTv16i8 || Opc == ARM_MVE_VPTv16u8 ||
	       Opc == ARM_MVE_VPTv16s8 || Opc == ARM_MVE_VPTv8i16 ||
	       Opc == ARM_MVE_VPTv8u16 || Opc == ARM_MVE_VPTv8s16 ||
	       Opc == ARM_MVE_VPTv4i32 || Opc == ARM_MVE_VPTv4u32 ||
	       Opc == ARM_MVE_VPTv4s32 || Opc == ARM_MVE_VPTv4f32 ||
	       Opc == ARM_MVE_VPTv8f16 || Opc == ARM_MVE_VPTv16i8r ||
	       Opc == ARM_MVE_VPTv16u8r || Opc == ARM_MVE_VPTv16s8r ||
	       Opc == ARM_MVE_VPTv8i16r || Opc == ARM_MVE_VPTv8u16r ||
	       Opc == ARM_MVE_VPTv8s16r || Opc == ARM_MVE_VPTv4i32r ||
	       Opc == ARM_MVE_VPTv4u32r || Opc == ARM_MVE_VPTv4s32r ||
	       Opc == ARM_MVE_VPTv4f32r || Opc == ARM_MVE_VPTv8f16r ||
	       Opc == ARM_MVE_VPST;
}

// Imported from ARMMCTargetDesc.cpp
bool ARM_isCDECoproc(size_t Coproc, const MCInst *MI)
{
	// Unfortunately we don't have ARMTargetInfo in the disassembler, so we have
	// to rely on feature bits.
	if (Coproc >= 8)
		return false;

	return ARM_getFeatureBits(MI->csh->mode,
				  ARM_FeatureCoprocCDE0 + Coproc);
}

// Hacky: enable all features for disassembler
bool ARM_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == ARM_ModeThumb) {
		if (mode & CS_MODE_THUMB)
			return true;
		return false;
	}

	if (feature == ARM_FeatureDFB)
		return false;

	if (feature == ARM_FeatureRAS)
		return false;

	if (feature == ARM_FeatureMClass && (mode & CS_MODE_MCLASS) == 0)
		return false;

	if ((feature == ARM_HasMVEIntegerOps || feature == ARM_HasMVEFloatOps ||
	     feature == ARM_FeatureMVEVectorCostFactor1 ||
	     feature == ARM_FeatureMVEVectorCostFactor2 ||
	     feature == ARM_FeatureMVEVectorCostFactor4) &&
	    (mode & CS_MODE_MCLASS) == 0)
		return false;

	if ((feature == ARM_HasV8Ops || feature == ARM_HasV8_1MMainlineOps ||
	     feature == ARM_HasV8_1aOps || feature == ARM_HasV8_2aOps ||
	     feature == ARM_HasV8_3aOps || feature == ARM_HasV8_4aOps ||
	     feature == ARM_HasV8_5aOps || feature == ARM_HasV8_6aOps ||
	     feature == ARM_HasV8_7aOps || feature == ARM_HasV8_8aOps ||
	     feature == ARM_HasV8_9aOps) &&
	    (mode & CS_MODE_V8) == 0)
		return false;

	if (feature >= ARM_FeatureCoprocCDE0 &&
	    feature <= ARM_FeatureCoprocCDE7)
		// We currently have no way to detect CDE (Custom-Datapath-Extension)
		// coprocessors.
		return false;

	// we support everything
	return true;
}
