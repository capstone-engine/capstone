//===-- ARMBaseInfo.h - Top level definitions for ARM ---*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone helper functions and enum definitions for
// the ARM target useful for the compiler back-end and the MC libraries.
// As such, it deliberately does not include references to LLVM core
// code gen types, passes, etc..
//
//===----------------------------------------------------------------------===//

#ifndef CS_ARM_BASEINFO_H
#define CS_ARM_BASEINFO_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../../MCInstPrinter.h"
#include "../../cs_priv.h"
#include "capstone/arm.h"

#define GET_INSTRINFO_ENUM
#include "ARMGenInstrInfo.inc"

// System Registers
typedef struct MClassSysReg {
	const char *Name;
	arm_sysop_reg sysreg;
	uint16_t M1Encoding12;
	uint16_t M2M3Encoding8;
	uint16_t Encoding;
	int FeaturesRequired[2];
} ARMSysReg_MClassSysReg;

// return true if FeaturesRequired are all present in ActiveFeatures
static inline bool hasRequiredFeatures(const ARMSysReg_MClassSysReg *TheReg,
				       int ActiveFeatures)
{
	return (TheReg->FeaturesRequired[0] == ActiveFeatures ||
		TheReg->FeaturesRequired[1] == ActiveFeatures);
}

// returns true if TestFeatures are all present in FeaturesRequired
static inline bool
MClassSysReg_isInRequiredFeatures(const ARMSysReg_MClassSysReg *TheReg,
				  int TestFeatures)
{
	return (TheReg->FeaturesRequired[0] == TestFeatures ||
		TheReg->FeaturesRequired[1] == TestFeatures);
}

#define GET_SUBTARGETINFO_ENUM
#include "ARMGenSubtargetInfo.inc"

// lookup system register using 12-bit SYSm value.
// Note: the search is uniqued using M1 mask
const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegBy12bitSYSmValue(unsigned SYSm);
// returns APSR with _<bits> qualifier.
// Note: ARMv7-M deprecates using MSR APSR without a _<bits> qualifier
const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegAPSRNonDeprecated(unsigned SYSm);
// lookup system registers using 8-bit SYSm value
const ARMSysReg_MClassSysReg *
ARMSysReg_lookupMClassSysRegBy8bitSYSmValue(unsigned SYSm);
// end namespace ARMSysReg

// Banked Registers
typedef struct BankedReg {
	const char *Name;
	arm_sysop_reg sysreg;
	uint16_t Encoding;
} ARMBankedReg_BankedReg;

#define GET_BANKEDREG_DECL
#define GET_MCLASSSYSREG_DECL
#include "ARMGenSystemRegister.inc"

typedef enum IMod { ARM_PROC_IE = 2, ARM_PROC_ID = 3 } ARM_PROC_IMod;

typedef enum IFlags {
	ARM_PROC_F = 1,
	ARM_PROC_I = 2,
	ARM_PROC_A = 4
} ARM_PROC_IFlags;

inline static const char *ARM_PROC_IFlagsToString(unsigned val)
{
	switch (val) {
	default:
		// llvm_unreachable("Unknown iflags operand");
	case ARM_PROC_F:
		return "f";
	case ARM_PROC_I:
		return "i";
	case ARM_PROC_A:
		return "a";
	}
}

inline static const char *ARM_PROC_IModToString(unsigned val)
{
	switch (val) {
	default:
		CS_ASSERT_RET_VAL("Unknown imod operand", NULL);
	case ARM_PROC_IE:
		return "ie";
	case ARM_PROC_ID:
		return "id";
	}
}

inline static const char *ARM_MB_MemBOptToString(unsigned val, bool HasV8)
{
	switch (val) {
	default:
		CS_ASSERT_RET_VAL("Unknown memory operation", NULL);
	case ARM_MB_SY:
		return "sy";
	case ARM_MB_ST:
		return "st";
	case ARM_MB_LD:
		return HasV8 ? "ld" : "#0xd";
	case ARM_MB_RESERVED_12:
		return "#0xc";
	case ARM_MB_ISH:
		return "ish";
	case ARM_MB_ISHST:
		return "ishst";
	case ARM_MB_ISHLD:
		return HasV8 ? "ishld" : "#0x9";
	case ARM_MB_RESERVED_8:
		return "#0x8";
	case ARM_MB_NSH:
		return "nsh";
	case ARM_MB_NSHST:
		return "nshst";
	case ARM_MB_NSHLD:
		return HasV8 ? "nshld" : "#0x5";
	case ARM_MB_RESERVED_4:
		return "#0x4";
	case ARM_MB_OSH:
		return "osh";
	case ARM_MB_OSHST:
		return "oshst";
	case ARM_MB_OSHLD:
		return HasV8 ? "oshld" : "#0x1";
	case ARM_MB_RESERVED_0:
		return "#0x0";
	}
}

typedef enum TraceSyncBOpt { ARM_TSB_CSYNC = 0 } ARM_TSB_TraceSyncBOpt;

inline static const char *ARM_TSB_TraceSyncBOptToString(unsigned val)
{
	switch (val) {
	default:
		CS_ASSERT_RET_VAL("Unknown trace synchronization barrier operation", NULL);
	case ARM_TSB_CSYNC:
		return "csync";
	}
}

typedef enum InstSyncBOpt {
	ARM_ISB_RESERVED_0 = 0,
	ARM_ISB_RESERVED_1 = 1,
	ARM_ISB_RESERVED_2 = 2,
	ARM_ISB_RESERVED_3 = 3,
	ARM_ISB_RESERVED_4 = 4,
	ARM_ISB_RESERVED_5 = 5,
	ARM_ISB_RESERVED_6 = 6,
	ARM_ISB_RESERVED_7 = 7,
	ARM_ISB_RESERVED_8 = 8,
	ARM_ISB_RESERVED_9 = 9,
	ARM_ISB_RESERVED_10 = 10,
	ARM_ISB_RESERVED_11 = 11,
	ARM_ISB_RESERVED_12 = 12,
	ARM_ISB_RESERVED_13 = 13,
	ARM_ISB_RESERVED_14 = 14,
	ARM_ISB_SY = 15
} ARM_ISB_InstSyncBOpt;

inline static const char *ARM_ISB_InstSyncBOptToString(unsigned val)
{
	switch (val) {
	default:
		CS_ASSERT_RET_VAL("Unknown memory operation", NULL);
	case ARM_ISB_RESERVED_0:
		return "#0x0";
	case ARM_ISB_RESERVED_1:
		return "#0x1";
	case ARM_ISB_RESERVED_2:
		return "#0x2";
	case ARM_ISB_RESERVED_3:
		return "#0x3";
	case ARM_ISB_RESERVED_4:
		return "#0x4";
	case ARM_ISB_RESERVED_5:
		return "#0x5";
	case ARM_ISB_RESERVED_6:
		return "#0x6";
	case ARM_ISB_RESERVED_7:
		return "#0x7";
	case ARM_ISB_RESERVED_8:
		return "#0x8";
	case ARM_ISB_RESERVED_9:
		return "#0x9";
	case ARM_ISB_RESERVED_10:
		return "#0xa";
	case ARM_ISB_RESERVED_11:
		return "#0xb";
	case ARM_ISB_RESERVED_12:
		return "#0xc";
	case ARM_ISB_RESERVED_13:
		return "#0xd";
	case ARM_ISB_RESERVED_14:
		return "#0xe";
	case ARM_ISB_SY:
		return "sy";
	}
}

#define GET_REGINFO_ENUM
#include "ARMGenRegisterInfo.inc"

/// isARMLowRegister - Returns true if the register is a low register (r0-r7).
///
static inline bool isARMLowRegister(unsigned Reg)
{
	switch (Reg) {
	case ARM_R0:
	case ARM_R1:
	case ARM_R2:
	case ARM_R3:
	case ARM_R4:
	case ARM_R5:
	case ARM_R6:
	case ARM_R7:
		return true;
	default:
		return false;
	}
}

/// ARMII - This namespace holds all of the target specific flags that
/// instruction info tracks.
///
/// ARM Index Modes
typedef enum IndexMode {
	ARMII_IndexModeNone = 0,
	ARMII_IndexModePre = 1,
	ARMII_IndexModePost = 2,
	ARMII_IndexModeUpd = 3
} ARMII_IndexMode;

/// ARM Addressing Modes
typedef enum AddrMode {
	ARMII_AddrModeNone = 0,
	ARMII_AddrMode1 = 1,
	ARMII_AddrMode2 = 2,
	ARMII_AddrMode3 = 3,
	ARMII_AddrMode4 = 4,
	ARMII_AddrMode5 = 5,
	ARMII_AddrMode6 = 6,
	ARMII_AddrModeT1_1 = 7,
	ARMII_AddrModeT1_2 = 8,
	ARMII_AddrModeT1_4 = 9,
	ARMII_AddrModeT1_s = 10,     // i8 * 4 for pc and sp relative data
	ARMII_AddrModeT2_i12 = 11,
	ARMII_AddrModeT2_i8 = 12,    // +/- i8
	ARMII_AddrModeT2_i8pos = 13, // + i8
	ARMII_AddrModeT2_i8neg = 14, // - i8
	ARMII_AddrModeT2_so = 15,
	ARMII_AddrModeT2_pc = 16,    // +/- i12 for pc relative data
	ARMII_AddrModeT2_i8s4 = 17,  // i8 * 4
	ARMII_AddrMode_i12 = 18,
	ARMII_AddrMode5FP16 = 19,    // i8 * 2
	ARMII_AddrModeT2_ldrex = 20, // i8 * 4, with unscaled offset in MCInst
	ARMII_AddrModeT2_i7s4 = 21,  // i7 * 4
	ARMII_AddrModeT2_i7s2 = 22,  // i7 * 2
	ARMII_AddrModeT2_i7 = 23,    // i7 * 1
} ARMII_AddrMode;

inline static const char *ARMII_AddrModeToString(ARMII_AddrMode addrmode)
{
	switch (addrmode) {
	case ARMII_AddrModeNone:
		return "AddrModeNone";
	case ARMII_AddrMode1:
		return "AddrMode1";
	case ARMII_AddrMode2:
		return "AddrMode2";
	case ARMII_AddrMode3:
		return "AddrMode3";
	case ARMII_AddrMode4:
		return "AddrMode4";
	case ARMII_AddrMode5:
		return "AddrMode5";
	case ARMII_AddrMode5FP16:
		return "AddrMode5FP16";
	case ARMII_AddrMode6:
		return "AddrMode6";
	case ARMII_AddrModeT1_1:
		return "AddrModeT1_1";
	case ARMII_AddrModeT1_2:
		return "AddrModeT1_2";
	case ARMII_AddrModeT1_4:
		return "AddrModeT1_4";
	case ARMII_AddrModeT1_s:
		return "AddrModeT1_s";
	case ARMII_AddrModeT2_i12:
		return "AddrModeT2_i12";
	case ARMII_AddrModeT2_i8:
		return "AddrModeT2_i8";
	case ARMII_AddrModeT2_i8pos:
		return "AddrModeT2_i8pos";
	case ARMII_AddrModeT2_i8neg:
		return "AddrModeT2_i8neg";
	case ARMII_AddrModeT2_so:
		return "AddrModeT2_so";
	case ARMII_AddrModeT2_pc:
		return "AddrModeT2_pc";
	case ARMII_AddrModeT2_i8s4:
		return "AddrModeT2_i8s4";
	case ARMII_AddrMode_i12:
		return "AddrMode_i12";
	case ARMII_AddrModeT2_ldrex:
		return "AddrModeT2_ldrex";
	case ARMII_AddrModeT2_i7s4:
		return "AddrModeT2_i7s4";
	case ARMII_AddrModeT2_i7s2:
		return "AddrModeT2_i7s2";
	case ARMII_AddrModeT2_i7:
		return "AddrModeT2_i7";
	}
}

/// Target Operand Flag enum.
typedef enum TOF {
	//===------------------------------------------------------------------===//
	// ARM Specific MachineOperand flags.

	ARMII_MO_NO_FLAG = 0,

	/// MO_LO16 - On a symbol operand, this represents a relocation containing
	/// lower 16 bit of the address. Used only via movw instruction.
	ARMII_MO_LO16 = 0x1,

	/// MO_HI16 - On a symbol operand, this represents a relocation containing
	/// higher 16 bit of the address. Used only via movt instruction.
	ARMII_MO_HI16 = 0x2,

	/// MO_OPTION_MASK - Most flags are mutually exclusive; this mask selects
	/// just that part of the flag set.
	ARMII_MO_OPTION_MASK = 0x3,

	/// MO_COFFSTUB - On a symbol operand "FOO", this indicates that the
	/// reference is actually to the ".refptr.FOO" symbol.  This is used for
	/// stub symbols on windows.
	ARMII_MO_COFFSTUB = 0x4,

	/// MO_GOT - On a symbol operand, this represents a GOT relative relocation.
	ARMII_MO_GOT = 0x8,

	/// MO_SBREL - On a symbol operand, this represents a static base relative
	/// relocation. Used in movw and movt instructions.
	ARMII_MO_SBREL = 0x10,

	/// MO_DLLIMPORT - On a symbol operand, this represents that the reference
	/// to the symbol is for an import stub.  This is used for DLL import
	/// storage class indication on Windows.
	ARMII_MO_DLLIMPORT = 0x20,

	/// MO_SECREL - On a symbol operand this indicates that the immediate is
	/// the offset from beginning of section.
	///
	/// This is the TLS offset for the COFF/Windows TLS mechanism.
	ARMII_MO_SECREL = 0x40,

	/// MO_NONLAZY - This is an independent flag, on a symbol operand "FOO" it
	/// represents a symbol which, if indirect, will get special Darwin mangling
	/// as a non-lazy-ptr indirect symbol (i.e. "L_FOO$non_lazy_ptr"). Can be
	/// combined with MO_LO16, MO_HI16 or MO_NO_FLAG (in a constant-pool, for
	/// example).
	ARMII_MO_NONLAZY = 0x80,

	// It's undefined behaviour if an enum overflows the range between its
	// smallest and largest values, but since these are |ed together, it can
	// happen. Put a sentinel in (values of this enum are stored as "unsigned
	// char").
	ARMII_MO_UNUSED_MAXIMUM = 0xff
} ARMII_TOF;

enum {
	//===------------------------------------------------------------------===//
	// Instruction Flags.

	//===------------------------------------------------------------------===//
	// This four-bit field describes the addressing mode used.
	ARMII_AddrModeMask =
		0x1f, // The AddrMode enums are declared in ARMBaseInfo.h

	// IndexMode - Unindex, pre-indexed, or post-indexed are valid for load
	// and store ops only.  Generic "updating" flag is used for ld/st multiple.
	// The index mode enums are declared in ARMBaseInfo.h
	ARMII_IndexModeShift = 5,
	ARMII_IndexModeMask = 3 << ARMII_IndexModeShift,

	//===------------------------------------------------------------------===//
	// Instruction encoding formats.
	//
	ARMII_FormShift = 7,
	ARMII_FormMask = 0x3f << ARMII_FormShift,

	// Pseudo instructions
	ARMII_Pseudo = 0 << ARMII_FormShift,

	// Multiply instructions
	ARMII_MulFrm = 1 << ARMII_FormShift,

	// Branch instructions
	ARMII_BrFrm = 2 << ARMII_FormShift,
	ARMII_BrMiscFrm = 3 << ARMII_FormShift,

	// Data Processing instructions
	ARMII_DPFrm = 4 << ARMII_FormShift,
	ARMII_DPSoRegFrm = 5 << ARMII_FormShift,

	// Load and Store
	ARMII_LdFrm = 6 << ARMII_FormShift,
	ARMII_StFrm = 7 << ARMII_FormShift,
	ARMII_LdMiscFrm = 8 << ARMII_FormShift,
	ARMII_StMiscFrm = 9 << ARMII_FormShift,
	ARMII_LdStMulFrm = 10 << ARMII_FormShift,

	ARMII_LdStExFrm = 11 << ARMII_FormShift,

	// Miscellaneous arithmetic instructions
	ARMII_ArithMiscFrm = 12 << ARMII_FormShift,
	ARMII_SatFrm = 13 << ARMII_FormShift,

	// Extend instructions
	ARMII_ExtFrm = 14 << ARMII_FormShift,

	// VFP formats
	ARMII_VFPUnaryFrm = 15 << ARMII_FormShift,
	ARMII_VFPBinaryFrm = 16 << ARMII_FormShift,
	ARMII_VFPConv1Frm = 17 << ARMII_FormShift,
	ARMII_VFPConv2Frm = 18 << ARMII_FormShift,
	ARMII_VFPConv3Frm = 19 << ARMII_FormShift,
	ARMII_VFPConv4Frm = 20 << ARMII_FormShift,
	ARMII_VFPConv5Frm = 21 << ARMII_FormShift,
	ARMII_VFPLdStFrm = 22 << ARMII_FormShift,
	ARMII_VFPLdStMulFrm = 23 << ARMII_FormShift,
	ARMII_VFPMiscFrm = 24 << ARMII_FormShift,

	// Thumb format
	ARMII_ThumbFrm = 25 << ARMII_FormShift,

	// Miscelleaneous format
	ARMII_MiscFrm = 26 << ARMII_FormShift,

	// NEON formats
	ARMII_NGetLnFrm = 27 << ARMII_FormShift,
	ARMII_NSetLnFrm = 28 << ARMII_FormShift,
	ARMII_NDupFrm = 29 << ARMII_FormShift,
	ARMII_NLdStFrm = 30 << ARMII_FormShift,
	ARMII_N1RegModImmFrm = 31 << ARMII_FormShift,
	ARMII_N2RegFrm = 32 << ARMII_FormShift,
	ARMII_NVCVTFrm = 33 << ARMII_FormShift,
	ARMII_NVDupLnFrm = 34 << ARMII_FormShift,
	ARMII_N2RegVShLFrm = 35 << ARMII_FormShift,
	ARMII_N2RegVShRFrm = 36 << ARMII_FormShift,
	ARMII_N3RegFrm = 37 << ARMII_FormShift,
	ARMII_N3RegVShFrm = 38 << ARMII_FormShift,
	ARMII_NVExtFrm = 39 << ARMII_FormShift,
	ARMII_NVMulSLFrm = 40 << ARMII_FormShift,
	ARMII_NVTBLFrm = 41 << ARMII_FormShift,
	ARMII_N3RegCplxFrm = 43 << ARMII_FormShift,

	//===------------------------------------------------------------------===//
	// Misc flags.

	// UnaryDP - Indicates this is a unary data processing instruction, i.e.
	// it doesn't have a Rn operand.
	ARMII_UnaryDP = 1 << 13,

	// Xform16Bit - Indicates this Thumb2 instruction may be transformed into
	// a 16-bit Thumb instruction if certain conditions are met.
	ARMII_Xform16Bit = 1 << 14,

	// ThumbArithFlagSetting - The instruction is a 16-bit flag setting Thumb
	// instruction. Used by the parser to determine whether to require the 'S'
	// suffix on the mnemonic (when not in an IT block) or preclude it (when
	// in an IT block).
	ARMII_ThumbArithFlagSetting = 1 << 19,

	// Whether an instruction can be included in an MVE tail-predicated loop,
	// though extra validity checks may need to be performed too.
	ARMII_ValidForTailPredication = 1 << 20,

	// Whether an instruction writes to the top/bottom half of a vector element
	// and leaves the other half untouched.
	ARMII_RetainsPreviousHalfElement = 1 << 21,

	// Whether the instruction produces a scalar result from vector operands.
	ARMII_HorizontalReduction = 1 << 22,

	// Whether this instruction produces a vector result that is larger than
	// its input, typically reading from the top/bottom halves of the input(s).
	ARMII_DoubleWidthResult = 1 << 23,

	// The vector element size for MVE instructions. 00 = i8, 01 = i16, 10 = i32
	// and 11 = i64. This is the largest type if multiple are present, so a
	// MVE_VMOVLs8bh is ize 01=i16, as it extends from a i8 to a i16. There are
	// some caveats so cannot be used blindly, such as exchanging VMLADAVA's and
	// complex instructions, which may use different input lanes.
	ARMII_VecSizeShift = 24,
	ARMII_VecSize = 3 << ARMII_VecSizeShift,

	//===------------------------------------------------------------------===//
	// Code domain.
	ARMII_DomainShift = 15,
	ARMII_DomainMask = 15 << ARMII_DomainShift,
	ARMII_DomainGeneral = 0 << ARMII_DomainShift,
	ARMII_DomainVFP = 1 << ARMII_DomainShift,
	ARMII_DomainNEON = 2 << ARMII_DomainShift,
	ARMII_DomainNEONA8 = 4 << ARMII_DomainShift,
	ARMII_DomainMVE = 8 << ARMII_DomainShift,

	//===------------------------------------------------------------------===//
	// Field shifts - such shifts are used to set field while generating
	// machine instructions.
	//
	// FIXME: This list will need adjusting/fixing as the MC code emitter
	// takes shape and the ARMCodeEmitter.cpp bits go away.
	ARMII_ShiftTypeShift = 4,

	ARMII_M_BitShift = 5,
	ARMII_ShiftImmShift = 5,
	ARMII_ShiftShift = 7,
	ARMII_N_BitShift = 7,
	ARMII_ImmHiShift = 8,
	ARMII_SoRotImmShift = 8,
	ARMII_RegRsShift = 8,
	ARMII_ExtRotImmShift = 10,
	ARMII_RegRdLoShift = 12,
	ARMII_RegRdShift = 12,
	ARMII_RegRdHiShift = 16,
	ARMII_RegRnShift = 16,
	ARMII_S_BitShift = 20,
	ARMII_W_BitShift = 21,
	ARMII_AM3_I_BitShift = 22,
	ARMII_D_BitShift = 22,
	ARMII_U_BitShift = 23,
	ARMII_P_BitShift = 24,
	ARMII_I_BitShift = 25,
	ARMII_CondShift = 28
};

const char *get_pred_mask(ARM_PredBlockMask pred_mask);

#endif // CS_ARM_BASEINFO_H
