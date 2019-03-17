//===-- AArch64BaseInfo.h - Top level definitions for AArch64- --*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone helper functions and enum definitions for
// the AArch64 target useful for the compiler back-end and the MC libraries.
// As such, it deliberately does not include references to LLVM core
// code gen types, passes, etc..
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_LLVM_AARCH64_BASEINFO_H
#define CS_LLVM_AARCH64_BASEINFO_H

#include <ctype.h>
#include <string.h>

#ifndef __cplusplus
#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#define inline /* inline */
#endif
#endif

inline static unsigned getWRegFromXReg(unsigned Reg)
{
	switch (Reg) {
		case ARM64_REG_X0: return ARM64_REG_W0;
		case ARM64_REG_X1: return ARM64_REG_W1;
		case ARM64_REG_X2: return ARM64_REG_W2;
		case ARM64_REG_X3: return ARM64_REG_W3;
		case ARM64_REG_X4: return ARM64_REG_W4;
		case ARM64_REG_X5: return ARM64_REG_W5;
		case ARM64_REG_X6: return ARM64_REG_W6;
		case ARM64_REG_X7: return ARM64_REG_W7;
		case ARM64_REG_X8: return ARM64_REG_W8;
		case ARM64_REG_X9: return ARM64_REG_W9;
		case ARM64_REG_X10: return ARM64_REG_W10;
		case ARM64_REG_X11: return ARM64_REG_W11;
		case ARM64_REG_X12: return ARM64_REG_W12;
		case ARM64_REG_X13: return ARM64_REG_W13;
		case ARM64_REG_X14: return ARM64_REG_W14;
		case ARM64_REG_X15: return ARM64_REG_W15;
		case ARM64_REG_X16: return ARM64_REG_W16;
		case ARM64_REG_X17: return ARM64_REG_W17;
		case ARM64_REG_X18: return ARM64_REG_W18;
		case ARM64_REG_X19: return ARM64_REG_W19;
		case ARM64_REG_X20: return ARM64_REG_W20;
		case ARM64_REG_X21: return ARM64_REG_W21;
		case ARM64_REG_X22: return ARM64_REG_W22;
		case ARM64_REG_X23: return ARM64_REG_W23;
		case ARM64_REG_X24: return ARM64_REG_W24;
		case ARM64_REG_X25: return ARM64_REG_W25;
		case ARM64_REG_X26: return ARM64_REG_W26;
		case ARM64_REG_X27: return ARM64_REG_W27;
		case ARM64_REG_X28: return ARM64_REG_W28;
		case ARM64_REG_FP: return ARM64_REG_W29;
		case ARM64_REG_LR: return ARM64_REG_W30;
		case ARM64_REG_SP: return ARM64_REG_WSP;
		case ARM64_REG_XZR: return ARM64_REG_WZR;
	}

	// For anything else, return it unchanged.
	return Reg;
}

inline static unsigned getXRegFromWReg(unsigned Reg)
{
	switch (Reg) {
		case ARM64_REG_W0: return ARM64_REG_X0;
		case ARM64_REG_W1: return ARM64_REG_X1;
		case ARM64_REG_W2: return ARM64_REG_X2;
		case ARM64_REG_W3: return ARM64_REG_X3;
		case ARM64_REG_W4: return ARM64_REG_X4;
		case ARM64_REG_W5: return ARM64_REG_X5;
		case ARM64_REG_W6: return ARM64_REG_X6;
		case ARM64_REG_W7: return ARM64_REG_X7;
		case ARM64_REG_W8: return ARM64_REG_X8;
		case ARM64_REG_W9: return ARM64_REG_X9;
		case ARM64_REG_W10: return ARM64_REG_X10;
		case ARM64_REG_W11: return ARM64_REG_X11;
		case ARM64_REG_W12: return ARM64_REG_X12;
		case ARM64_REG_W13: return ARM64_REG_X13;
		case ARM64_REG_W14: return ARM64_REG_X14;
		case ARM64_REG_W15: return ARM64_REG_X15;
		case ARM64_REG_W16: return ARM64_REG_X16;
		case ARM64_REG_W17: return ARM64_REG_X17;
		case ARM64_REG_W18: return ARM64_REG_X18;
		case ARM64_REG_W19: return ARM64_REG_X19;
		case ARM64_REG_W20: return ARM64_REG_X20;
		case ARM64_REG_W21: return ARM64_REG_X21;
		case ARM64_REG_W22: return ARM64_REG_X22;
		case ARM64_REG_W23: return ARM64_REG_X23;
		case ARM64_REG_W24: return ARM64_REG_X24;
		case ARM64_REG_W25: return ARM64_REG_X25;
		case ARM64_REG_W26: return ARM64_REG_X26;
		case ARM64_REG_W27: return ARM64_REG_X27;
		case ARM64_REG_W28: return ARM64_REG_X28;
		case ARM64_REG_W29: return ARM64_REG_FP;
		case ARM64_REG_W30: return ARM64_REG_LR;
		case ARM64_REG_WSP: return ARM64_REG_SP;
		case ARM64_REG_WZR: return ARM64_REG_XZR;

	// For anything else, return it unchanged.
	return Reg;
}

inline static unsigned getBRegFromDReg(unsigned Reg)
{
	switch (Reg) {
		case ARM64_REG_D0:  return ARM64_REG_B0;
		case ARM64_REG_D1:  return ARM64_REG_B1;
		case ARM64_REG_D2:  return ARM64_REG_B2;
		case ARM64_REG_D3:  return ARM64_REG_B3;
		case ARM64_REG_D4:  return ARM64_REG_B4;
		case ARM64_REG_D5:  return ARM64_REG_B5;
		case ARM64_REG_D6:  return ARM64_REG_B6;
		case ARM64_REG_D7:  return ARM64_REG_B7;
		case ARM64_REG_D8:  return ARM64_REG_B8;
		case ARM64_REG_D9:  return ARM64_REG_B9;
		case ARM64_REG_D10: return ARM64_REG_B10;
		case ARM64_REG_D11: return ARM64_REG_B11;
		case ARM64_REG_D12: return ARM64_REG_B12;
		case ARM64_REG_D13: return ARM64_REG_B13;
		case ARM64_REG_D14: return ARM64_REG_B14;
		case ARM64_REG_D15: return ARM64_REG_B15;
		case ARM64_REG_D16: return ARM64_REG_B16;
		case ARM64_REG_D17: return ARM64_REG_B17;
		case ARM64_REG_D18: return ARM64_REG_B18;
		case ARM64_REG_D19: return ARM64_REG_B19;
		case ARM64_REG_D20: return ARM64_REG_B20;
		case ARM64_REG_D21: return ARM64_REG_B21;
		case ARM64_REG_D22: return ARM64_REG_B22;
		case ARM64_REG_D23: return ARM64_REG_B23;
		case ARM64_REG_D24: return ARM64_REG_B24;
		case ARM64_REG_D25: return ARM64_REG_B25;
		case ARM64_REG_D26: return ARM64_REG_B26;
		case ARM64_REG_D27: return ARM64_REG_B27;
		case ARM64_REG_D28: return ARM64_REG_B28;
		case ARM64_REG_D29: return ARM64_REG_B29;
		case ARM64_REG_D30: return ARM64_REG_B30;
		case ARM64_REG_D31: return ARM64_REG_B31;
	}

	// For anything else, return it unchanged.
	return Reg;
}

inline static unsigned getDRegFromBReg(unsigned Reg)
{
	switch (Reg) {
		case ARM64_REG_B0:  return ARM64_REG_D0;
		case ARM64_REG_B1:  return ARM64_REG_D1;
		case ARM64_REG_B2:  return ARM64_REG_D2;
		case ARM64_REG_B3:  return ARM64_REG_D3;
		case ARM64_REG_B4:  return ARM64_REG_D4;
		case ARM64_REG_B5:  return ARM64_REG_D5;
		case ARM64_REG_B6:  return ARM64_REG_D6;
		case ARM64_REG_B7:  return ARM64_REG_D7;
		case ARM64_REG_B8:  return ARM64_REG_D8;
		case ARM64_REG_B9:  return ARM64_REG_D9;
		case ARM64_REG_B10: return ARM64_REG_D10;
		case ARM64_REG_B11: return ARM64_REG_D11;
		case ARM64_REG_B12: return ARM64_REG_D12;
		case ARM64_REG_B13: return ARM64_REG_D13;
		case ARM64_REG_B14: return ARM64_REG_D14;
		case ARM64_REG_B15: return ARM64_REG_D15;
		case ARM64_REG_B16: return ARM64_REG_D16;
		case ARM64_REG_B17: return ARM64_REG_D17;
		case ARM64_REG_B18: return ARM64_REG_D18;
		case ARM64_REG_B19: return ARM64_REG_D19;
		case ARM64_REG_B20: return ARM64_REG_D20;
		case ARM64_REG_B21: return ARM64_REG_D21;
		case ARM64_REG_B22: return ARM64_REG_D22;
		case ARM64_REG_B23: return ARM64_REG_D23;
		case ARM64_REG_B24: return ARM64_REG_D24;
		case ARM64_REG_B25: return ARM64_REG_D25;
		case ARM64_REG_B26: return ARM64_REG_D26;
		case ARM64_REG_B27: return ARM64_REG_D27;
		case ARM64_REG_B28: return ARM64_REG_D28;
		case ARM64_REG_B29: return ARM64_REG_D29;
		case ARM64_REG_B30: return ARM64_REG_D30;
		case ARM64_REG_B31: return ARM64_REG_D31;
	}

	// For anything else, return it unchanged.
	return Reg;
}
// // Enums corresponding to AArch64 condition codes
// The CondCodes constants map directly to the 4-bit encoding of the
// condition field for predicated instructions.
typedef enum A64CC_CondCode { // Meaning (integer)     Meaning (floating-point)
	A64CC_EQ = 0,        // Equal                      Equal
	A64CC_NE,            // Not equal                  Not equal, or unordered
	A64CC_HS,            // Unsigned higher or same    >, ==, or unordered
	A64CC_LO,            // Unsigned lower or same     Less than
	A64CC_MI,            // Minus, negative            Less than
	A64CC_PL,            // Plus, positive or zero     >, ==, or unordered
	A64CC_VS,            // Overflow                   Unordered
	A64CC_VC,            // No overflow                Ordered
	A64CC_HI,            // Unsigned higher            Greater than, or unordered
	A64CC_LS,            // Unsigned lower or same     Less than or equal
	A64CC_GE,            // Greater than or equal      Greater than or equal
	A64CC_LT,            // Less than                  Less than, or unordered
	A64CC_GT,            // Signed greater than        Greater than
	A64CC_LE,            // Signed less than or equal  <, ==, or unordered
	A64CC_AL,            // Always (unconditional)     Always (unconditional)
	A64CC_NV,             // Always (unconditional)     Always (unconditional)
	// Note the NV exists purely to disassemble 0b1111. Execution is "always".
	A64CC_Invalid
} A64CC_CondCode;

inline static const char *getCondCodeName(A64CC_CondCode CC)
{
	switch (CC) {
		default: return NULL;	// never reach
		case A64CC_EQ:  return "eq";
		case A64CC_NE:  return "ne";
		case A64CC_HS:  return "hs";
		case A64CC_LO:  return "lo";
		case A64CC_MI:  return "mi";
		case A64CC_PL:  return "pl";
		case A64CC_VS:  return "vs";
		case A64CC_VC:  return "vc";
		case A64CC_HI:  return "hi";
		case A64CC_LS:  return "ls";
		case A64CC_GE:  return "ge";
		case A64CC_LT:  return "lt";
		case A64CC_GT:  return "gt";
		case A64CC_LE:  return "le";
		case A64CC_AL:  return "al";
		case A64CC_NV:  return "nv";
	}
}

inline static A64CC_CondCode getInvertedCondCode(A64CC_CondCode Code)
{
	// To reverse a condition it's necessary to only invert the low bit:
	return (A64CC_CondCode)((unsigned)Code ^ 0x1);
}

/// Given a condition code, return NZCV flags that would satisfy that condition.
/// The flag bits are in the format expected by the ccmp instructions.
/// Note that many different flag settings can satisfy a given condition code,
/// this function just returns one of them.
inline static unsigned getNZCVToSatisfyCondCode(CondCode Code)
{
	// NZCV flags encoded as expected by ccmp instructions, ARMv8 ISA 5.5.7.
	enum { N = 8, Z = 4, C = 2, V = 1 };
	switch (Code) {
		default: // llvm_unreachable("Unknown condition code");
		case EQ: return Z; // Z == 1
		case NE: return 0; // Z == 0
		case HS: return C; // C == 1
		case LO: return 0; // C == 0
		case MI: return N; // N == 1
		case PL: return 0; // N == 0
		case VS: return V; // V == 1
		case VC: return 0; // V == 0
		case HI: return C; // C == 1 && Z == 0
		case LS: return 0; // C == 0 || Z == 1
		case GE: return 0; // N == V
		case LT: return N; // N != V
		case GT: return 0; // Z == 0 && N == V
		case LE: return Z; // Z == 1 || N != V
	}
}

/// Instances of this class can perform bidirectional mapping from random
/// identifier strings to operand encodings. For example "MSR" takes a named
/// system-register which must be encoded somehow and decoded for printing. This
/// central location means that the information for those transformations is not
/// duplicated and remains in sync.
///
/// FIXME: currently the algorithm is a completely unoptimised linear
/// search. Obviously this could be improved, but we would probably want to work
/// out just how often these instructions are emitted before working on it. It
/// might even be optimal to just reorder the tables for the common instructions
/// rather than changing the algorithm.
typedef struct A64NamedImmMapper_Mapping {
	const char *Name;
	uint32_t Value;
} A64NamedImmMapper_Mapping;

typedef struct A64NamedImmMapper {
	const A64NamedImmMapper_Mapping *Pairs;
	size_t NumPairs;
	uint32_t TooBigImm;
} A64NamedImmMapper;

typedef struct A64SysRegMapper {
	const A64NamedImmMapper_Mapping *SysRegPairs;
	const A64NamedImmMapper_Mapping *InstPairs;
	size_t NumInstPairs;
} A64SysRegMapper;

extern const A64SysRegMapper AArch64_MSRMapper;
extern const A64SysRegMapper AArch64_MRSMapper;

extern const A64NamedImmMapper A64DB_DBarrierMapper;
extern const A64NamedImmMapper A64AT_ATMapper;
extern const A64NamedImmMapper A64DC_DCMapper;
extern const A64NamedImmMapper A64IC_ICMapper;
extern const A64NamedImmMapper A64ISB_ISBMapper;
extern const A64NamedImmMapper A64PRFM_PRFMMapper;
extern const A64NamedImmMapper A64PState_PStateMapper;
extern const A64NamedImmMapper A64TLBI_TLBIMapper;

#include "AArch64GenSystemOperands.inc"

typedef enum A64SE_ShiftExtSpecifiers {
	A64SE_Invalid = -1,
	A64SE_LSL,
	A64SE_MSL,
	A64SE_LSR,
	A64SE_ASR,
	A64SE_ROR,

	A64SE_UXTB,
	A64SE_UXTH,
	A64SE_UXTW,
	A64SE_UXTX,

	A64SE_SXTB,
	A64SE_SXTH,
	A64SE_SXTW,
	A64SE_SXTX
} A64SE_ShiftExtSpecifiers;

typedef enum A64Layout_VectorLayout {
	A64Layout_Invalid = -1,
	A64Layout_VL_8B,
	A64Layout_VL_4H,
	A64Layout_VL_2S,
	A64Layout_VL_1D,

	A64Layout_VL_16B,
	A64Layout_VL_8H,
	A64Layout_VL_4S,
	A64Layout_VL_2D,

	// Bare layout for the 128-bit vector
	// (only show ".b", ".h", ".s", ".d" without vector number)
	A64Layout_VL_B,
	A64Layout_VL_H,
	A64Layout_VL_S,
	A64Layout_VL_D
} A64Layout_VectorLayout;

inline static const char *A64VectorLayoutToString(A64Layout_VectorLayout Layout)
{
	switch (Layout) {
		case A64Layout_VL_8B:  return ".8b";
		case A64Layout_VL_4H:  return ".4h";
		case A64Layout_VL_2S:  return ".2s";
		case A64Layout_VL_1D:  return ".1d";
		case A64Layout_VL_16B:  return ".16b";
		case A64Layout_VL_8H:  return ".8h";
		case A64Layout_VL_4S:  return ".4s";
		case A64Layout_VL_2D:  return ".2d";
		case A64Layout_VL_B:  return ".b";
		case A64Layout_VL_H:  return ".h";
		case A64Layout_VL_S:  return ".s";
		case A64Layout_VL_D:  return ".d";
		default: return NULL;	// never reach
	}
}

bool A64Imms_isLogicalImmBits(unsigned RegWidth, uint32_t Bits, uint64_t *Imm);

const char *A64NamedImmMapper_toString(const A64NamedImmMapper *N, uint32_t Value, bool *Valid);

uint32_t A64NamedImmMapper_fromString(const A64NamedImmMapper *N, char *Name, bool *Valid);

bool A64NamedImmMapper_validImm(const A64NamedImmMapper *N, uint32_t Value);

void A64SysRegMapper_toString(const A64SysRegMapper *S, uint32_t Bits, char *result);

/// Target Operand Flag enum.
enum TOF {
	//===------------------------------------------------------------------===//
	// AArch64 Specific MachineOperand flags.
	MO_NO_FLAG,
	MO_FRAGMENT = 0xf,
	/// MO_PAGE - A symbol operand with this flag represents the pc-relative
	/// offset of the 4K page containing the symbol.  This is used with the
	/// ADRP instruction.
	MO_PAGE = 1,
	/// MO_PAGEOFF - A symbol operand with this flag represents the offset of
	/// that symbol within a 4K page.  This offset is added to the page address
	/// to produce the complete address.
	MO_PAGEOFF = 2,
	/// MO_G3 - A symbol operand with this flag (granule 3) represents the high
	/// 16-bits of a 64-bit address, used in a MOVZ or MOVK instruction
	MO_G3 = 3,
	/// MO_G2 - A symbol operand with this flag (granule 2) represents the bits
	/// 32-47 of a 64-bit address, used in a MOVZ or MOVK instruction
	MO_G2 = 4,
	/// MO_G1 - A symbol operand with this flag (granule 1) represents the bits
	/// 16-31 of a 64-bit address, used in a MOVZ or MOVK instruction
	MO_G1 = 5,
	/// MO_G0 - A symbol operand with this flag (granule 0) represents the bits
	/// 0-15 of a 64-bit address, used in a MOVZ or MOVK instruction
	MO_G0 = 6,
	/// MO_HI12 - This flag indicates that a symbol operand represents the bits
	/// 13-24 of a 64-bit address, used in a arithmetic immediate-shifted-left-
	/// by-12-bits instruction.
	MO_HI12 = 7,
	/// MO_GOT - This flag indicates that a symbol operand represents the
	/// address of the GOT entry for the symbol, rather than the address of
	/// the symbol itself.
	MO_GOT = 0x10,
	/// MO_NC - Indicates whether the linker is expected to check the symbol
	/// reference for overflow. For example in an ADRP/ADD pair of relocations
	/// the ADRP usually does check, but not the ADD.
	MO_NC = 0x20,
	/// MO_TLS - Indicates that the operand being accessed is some kind of
	/// thread-local symbol. On Darwin, only one type of thread-local access
	/// exists (pre linker-relaxation), but on ELF the TLSModel used for the
	/// referee will affect interpretation.
	MO_TLS = 0x40,
	/// MO_DLLIMPORT - On a symbol operand, this represents that the reference
	/// to the symbol is for an import stub.  This is used for DLL import
	/// storage class indication on Windows.
	MO_DLLIMPORT = 0x80,
};

#endif
