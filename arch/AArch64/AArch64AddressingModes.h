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

//===- AArch64AddressingModes.h - AArch64 Addressing Modes ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the AArch64 addressing mode implementation stuff.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_AARCH64_MCTARGETDESC_AARCH64ADDRESSINGMODES_H
#define LLVM_LIB_TARGET_AARCH64_MCTARGETDESC_AARCH64ADDRESSINGMODES_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MathExtras.h"
#include <assert.h>
#include "../../MathExtras.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

/// AArch64_AM - AArch64 Addressing Mode Stuff
// CS namespace begin: AArch64_AM

//===----------------------------------------------------------------------===//
// Shifts
//
typedef enum ShiftExtendType {
	AArch64_AM_InvalidShiftExtend = -1,
	AArch64_AM_LSL = 0,
	AArch64_AM_LSR,
	AArch64_AM_ASR,
	AArch64_AM_ROR,
	AArch64_AM_MSL,

	AArch64_AM_UXTB,
	AArch64_AM_UXTH,
	AArch64_AM_UXTW,
	AArch64_AM_UXTX,

	AArch64_AM_SXTB,
	AArch64_AM_SXTH,
	AArch64_AM_SXTW,
	AArch64_AM_SXTX,
} AArch64_AM_ShiftExtendType;

/// getShiftName - Get the string encoding for the shift type.
static inline const char *
AArch64_AM_getShiftExtendName(AArch64_AM_ShiftExtendType ST)
{
	switch (ST) {
	default:
		CS_ASSERT_RET_VAL(0 && "unhandled shift type!", NULL);
	case AArch64_AM_LSL:
		return "lsl";
	case AArch64_AM_LSR:
		return "lsr";
	case AArch64_AM_ASR:
		return "asr";
	case AArch64_AM_ROR:
		return "ror";
	case AArch64_AM_MSL:
		return "msl";
	case AArch64_AM_UXTB:
		return "uxtb";
	case AArch64_AM_UXTH:
		return "uxth";
	case AArch64_AM_UXTW:
		return "uxtw";
	case AArch64_AM_UXTX:
		return "uxtx";
	case AArch64_AM_SXTB:
		return "sxtb";
	case AArch64_AM_SXTH:
		return "sxth";
	case AArch64_AM_SXTW:
		return "sxtw";
	case AArch64_AM_SXTX:
		return "sxtx";
	}
	return NULL;
}

/// getShiftType - Extract the shift type.
static inline AArch64_AM_ShiftExtendType AArch64_AM_getShiftType(unsigned Imm)
{
	switch ((Imm >> 6) & 0x7) {
	default:
		return AArch64_AM_InvalidShiftExtend;
	case 0:
		return AArch64_AM_LSL;
	case 1:
		return AArch64_AM_LSR;
	case 2:
		return AArch64_AM_ASR;
	case 3:
		return AArch64_AM_ROR;
	case 4:
		return AArch64_AM_MSL;
	}
}

/// getShiftValue - Extract the shift value.
static inline unsigned AArch64_AM_getShiftValue(unsigned Imm)
{
	return Imm & 0x3f;
}

/// getShifterImm - Encode the shift type and amount:
///   imm:     6-bit shift amount
///   shifter: 000 ==> lsl
///            001 ==> lsr
///            010 ==> asr
///            011 ==> ror
///            100 ==> msl
///   {8-6}  = shifter
///   {5-0}  = imm
static inline unsigned AArch64_AM_getShifterImm(AArch64_AM_ShiftExtendType ST,
						unsigned Imm)
{
	unsigned STEnc = 0;
	switch (ST) {
	default:
		CS_ASSERT_RET_VAL(0 && "Invalid shift requested", 0);
	case AArch64_AM_LSL:
		STEnc = 0;
		break;
	case AArch64_AM_LSR:
		STEnc = 1;
		break;
	case AArch64_AM_ASR:
		STEnc = 2;
		break;
	case AArch64_AM_ROR:
		STEnc = 3;
		break;
	case AArch64_AM_MSL:
		STEnc = 4;
		break;
	}
	return (STEnc << 6) | (Imm & 0x3f);
}

//===----------------------------------------------------------------------===//
// Extends
//
/// getArithShiftValue - get the arithmetic shift value.
static inline unsigned AArch64_AM_getArithShiftValue(unsigned Imm)
{
	return Imm & 0x7;
}

/// getExtendType - Extract the extend type for operands of arithmetic ops.
static inline AArch64_AM_ShiftExtendType AArch64_AM_getExtendType(unsigned Imm)
{
	switch (Imm) {
	default:
		CS_ASSERT_RET_VAL(0 && "Compiler bug!", 0);
	case 0:
		return AArch64_AM_UXTB;
	case 1:
		return AArch64_AM_UXTH;
	case 2:
		return AArch64_AM_UXTW;
	case 3:
		return AArch64_AM_UXTX;
	case 4:
		return AArch64_AM_SXTB;
	case 5:
		return AArch64_AM_SXTH;
	case 6:
		return AArch64_AM_SXTW;
	case 7:
		return AArch64_AM_SXTX;
	}
}

static inline AArch64_AM_ShiftExtendType
AArch64_AM_getArithExtendType(unsigned Imm)
{
	return AArch64_AM_getExtendType((Imm >> 3) & 0x7);
}

/// Mapping from extend bits to required operation:
///   shifter: 000 ==> uxtb
///            001 ==> uxth
///            010 ==> uxtw
///            011 ==> uxtx
///            100 ==> sxtb
///            101 ==> sxth
///            110 ==> sxtw
///            111 ==> sxtx
static inline unsigned
AArch64_AM_getExtendEncoding(AArch64_AM_ShiftExtendType ET)
{
	switch (ET) {
	default:
		CS_ASSERT_RET_VAL(0 && "Invalid extend type requested", 0);
	case AArch64_AM_UXTB:
		return 0;
		break;
	case AArch64_AM_UXTH:
		return 1;
		break;
	case AArch64_AM_UXTW:
		return 2;
		break;
	case AArch64_AM_UXTX:
		return 3;
		break;
	case AArch64_AM_SXTB:
		return 4;
		break;
	case AArch64_AM_SXTH:
		return 5;
		break;
	case AArch64_AM_SXTW:
		return 6;
		break;
	case AArch64_AM_SXTX:
		return 7;
		break;
	}
}

/// getArithExtendImm - Encode the extend type and shift amount for an
///                     arithmetic instruction:
///   imm:     3-bit extend amount
///   {5-3}  = shifter
///   {2-0}  = imm3
static inline unsigned
AArch64_AM_getArithExtendImm(AArch64_AM_ShiftExtendType ET, unsigned Imm)
{
	return (AArch64_AM_getExtendEncoding(ET) << 3) | (Imm & 0x7);
}

/// getMemDoShift - Extract the "do shift" flag value for load/store
/// instructions.
static inline bool AArch64_AM_getMemDoShift(unsigned Imm)
{
	return (Imm & 0x1) != 0;
}

/// getExtendType - Extract the extend type for the offset operand of
/// loads/stores.
static inline AArch64_AM_ShiftExtendType
AArch64_AM_getMemExtendType(unsigned Imm)
{
	return AArch64_AM_getExtendType((Imm >> 1) & 0x7);
}

/// getExtendImm - Encode the extend type and amount for a load/store inst:
///   doshift:     should the offset be scaled by the access size
///   shifter: 000 ==> uxtb
///            001 ==> uxth
///            010 ==> uxtw
///            011 ==> uxtx
///            100 ==> sxtb
///            101 ==> sxth
///            110 ==> sxtw
///            111 ==> sxtx
///   {3-1}  = shifter
///   {0}  = doshift
static inline unsigned AArch64_AM_getMemExtendImm(AArch64_AM_ShiftExtendType ET,
						  bool DoShift)
{
	return (AArch64_AM_getExtendEncoding(ET) << 1) | (unsigned)DoShift;
}

static inline uint64_t AArch64_AM_ror(uint64_t elt, unsigned size)
{
	return ((elt & 1) << (size - 1)) | (elt >> 1);
}

/// processLogicalImmediate - Determine if an immediate value can be encoded
/// as the immediate operand of a logical instruction for the given register
/// size.  If so, return true with "encoding" set to the encoded value in
/// the form N:immr:imms.
static inline bool AArch64_AM_processLogicalImmediate(uint64_t Imm,
						      unsigned RegSize,
						      uint64_t *Encoding)
{
	if (Imm == 0ULL || Imm == ~0ULL ||
	    (RegSize != 64 &&
	     (Imm >> RegSize != 0 || Imm == (~0ULL >> (64 - RegSize)))))
		return false;

	// First, determine the element size.
	unsigned Size = RegSize;

	do {
		Size /= 2;
		uint64_t Mask = (1ULL << Size) - 1;

		if ((Imm & Mask) != ((Imm >> Size) & Mask)) {
			Size *= 2;
			break;
		}
	} while (Size > 2);

	// Second, determine the rotation to make the element be: 0^m 1^n.
	uint32_t CTO, I;
	uint64_t Mask = ((uint64_t)-1LL) >> (64 - Size);
	Imm &= Mask;

	if (isShiftedMask_64(Imm)) {
		I = CountTrailingZeros_64(Imm);

		CTO = CountTrailingOnes_64(Imm >> I);
	} else {
		Imm |= ~Mask;
		if (!isShiftedMask_64(~Imm))
			return false;

		unsigned CLO = CountLeadingOnes_64(Imm);
		I = 64 - CLO;
		CTO = CLO + CountTrailingOnes_64(Imm) - (64 - Size);
	}

	// Encode in Immr the number of RORs it would take to get *from* 0^m 1^n
	// to our target value, where I is the number of RORs to go the opposite
	// direction.

	unsigned Immr = (Size - I) & (Size - 1);

	// If size has a 1 in the n'th bit, create a value that has zeroes in
	// bits [0, n] and ones above that.
	uint64_t NImms = ~(Size - 1) << 1;

	// Or the CTO value into the low bits, which must be below the Nth bit
	// bit mentioned above.
	NImms |= (CTO - 1);

	// Extract the seventh bit and toggle it to create the N field.
	unsigned N = ((NImms >> 6) & 1) ^ 1;

	*Encoding = (N << 12) | (Immr << 6) | (NImms & 0x3f);
	return true;
}

/// isLogicalImmediate - Return true if the immediate is valid for a logical
/// immediate instruction of the given register size. Return false otherwise.
static inline bool AArch64_AM_isLogicalImmediate(uint64_t imm, unsigned regSize)
{
	uint64_t encoding = 0;
	return AArch64_AM_processLogicalImmediate(imm, regSize, &encoding);
}

/// encodeLogicalImmediate - Return the encoded immediate value for a logical
/// immediate instruction of the given register size.
static inline uint64_t AArch64_AM_encodeLogicalImmediate(uint64_t imm,
							 unsigned regSize)
{
	uint64_t encoding = 0;
	bool res = AArch64_AM_processLogicalImmediate(imm, regSize, &encoding);

	(void)res;
	return encoding;
}

/// decodeLogicalImmediate - Decode a logical immediate value in the form
/// "N:immr:imms" (where the immr and imms fields are each 6 bits) into the
/// integer value it represents with regSize bits.
static inline uint64_t AArch64_AM_decodeLogicalImmediate(uint64_t val,
							 unsigned regSize)
{
	// Extract the N, imms, and immr fields.
	unsigned N = (val >> 12) & 1;
	unsigned immr = (val >> 6) & 0x3f;
	unsigned imms = val & 0x3f;

	int len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
	if (len < 1) {
		CS_ASSERT(len >= 1 && "Unhandled integer type");
		return 0;
	}

	unsigned size = (1 << len);
	unsigned R = immr & (size - 1);
	unsigned S = imms & (size - 1);

	uint64_t pattern = (1ULL << (S + 1)) - 1;
	for (unsigned i = 0; i < R; ++i)
		pattern = AArch64_AM_ror(pattern, size);

	// Replicate the pattern to fill the regSize.
	while (size != regSize) {
		pattern |= (pattern << size);
		size *= 2;
	}
	return pattern;
}

/// isValidDecodeLogicalImmediate - Check to see if the logical immediate value
/// in the form "N:immr:imms" (where the immr and imms fields are each 6 bits)
/// is a valid encoding for an integer value with regSize bits.
static inline bool AArch64_AM_isValidDecodeLogicalImmediate(uint64_t val,
							    unsigned regSize)
{
	// Extract the N and imms fields needed for checking.
	unsigned N = (val >> 12) & 1;
	unsigned imms = val & 0x3f;

	if (regSize == 32 && N != 0) // undefined logical immediate encoding
		return false;
	int len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
	if (len < 0) // undefined logical immediate encoding
		return false;
	unsigned size = (1 << len);
	unsigned S = imms & (size - 1);
	if (S == size - 1) // undefined logical immediate encoding
		return false;

	return true;
}

//===----------------------------------------------------------------------===//
// Floating-point Immediates
//
static inline float AArch64_AM_getFPImmFloat(unsigned Imm)
{
	// We expect an 8-bit binary encoding of a floating-point number here.

	uint32_t Sign = (Imm >> 7) & 0x1;
	uint32_t Exp = (Imm >> 4) & 0x7;
	uint32_t Mantissa = Imm & 0xf;

	//   8-bit FP    IEEE Float Encoding
	//   abcd efgh   aBbbbbbc defgh000 00000000 00000000
	//
	// where B = NOT(b);

	uint32_t I = 0;
	I |= Sign << 31;
	I |= ((Exp & 0x4) != 0 ? 0 : 1) << 30;
	I |= ((Exp & 0x4) != 0 ? 0x1f : 0) << 25;
	I |= (Exp & 0x3) << 23;
	I |= Mantissa << 19;
	return BitsToFloat(I);
}

//===--------------------------------------------------------------------===//
// AdvSIMD Modified Immediates
//===--------------------------------------------------------------------===//
// 0x00 0x00 0x00 abcdefgh 0x00 0x00 0x00 abcdefgh
static inline bool AArch64_AM_isAdvSIMDModImmType1(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0xffffff00ffffff00ULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType1(uint64_t Imm)
{
	return (Imm & 0xffULL);
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType1(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 32) | EncVal;
}

// 0x00 0x00 abcdefgh 0x00 0x00 0x00 abcdefgh 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType2(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0xffff00ffffff00ffULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType2(uint64_t Imm)
{
	return (Imm & 0xff00ULL) >> 8;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType2(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 40) | (EncVal << 8);
}

// 0x00 abcdefgh 0x00 0x00 0x00 abcdefgh 0x00 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType3(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0xff00ffffff00ffffULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType3(uint64_t Imm)
{
	return (Imm & 0xff0000ULL) >> 16;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType3(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 48) | (EncVal << 16);
}

// abcdefgh 0x00 0x00 0x00 abcdefgh 0x00 0x00 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType4(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0x00ffffff00ffffffULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType4(uint64_t Imm)
{
	return (Imm & 0xff000000ULL) >> 24;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType4(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 56) | (EncVal << 24);
}

// 0x00 abcdefgh 0x00 abcdefgh 0x00 abcdefgh 0x00 abcdefgh
static inline bool AArch64_AM_isAdvSIMDModImmType5(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       (((Imm & 0x00ff0000ULL) >> 16) == (Imm & 0x000000ffULL)) &&
	       ((Imm & 0xff00ff00ff00ff00ULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType5(uint64_t Imm)
{
	return (Imm & 0xffULL);
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType5(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 48) | (EncVal << 32) | (EncVal << 16) | EncVal;
}

// abcdefgh 0x00 abcdefgh 0x00 abcdefgh 0x00 abcdefgh 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType6(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       (((Imm & 0xff000000ULL) >> 16) == (Imm & 0x0000ff00ULL)) &&
	       ((Imm & 0x00ff00ff00ff00ffULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType6(uint64_t Imm)
{
	return (Imm & 0xff00ULL) >> 8;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType6(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 56) | (EncVal << 40) | (EncVal << 24) | (EncVal << 8);
}

// 0x00 0x00 abcdefgh 0xFF 0x00 0x00 abcdefgh 0xFF
static inline bool AArch64_AM_isAdvSIMDModImmType7(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0xffff00ffffff00ffULL) == 0x000000ff000000ffULL);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType7(uint64_t Imm)
{
	return (Imm & 0xff00ULL) >> 8;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType7(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 40) | (EncVal << 8) | 0x000000ff000000ffULL;
}

// 0x00 abcdefgh 0xFF 0xFF 0x00 abcdefgh 0xFF 0xFF
static inline bool AArch64_AM_isAdvSIMDModImmType8(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm & 0xff00ffffff00ffffULL) == 0x0000ffff0000ffffULL);
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType8(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	return (EncVal << 48) | (EncVal << 16) | 0x0000ffff0000ffffULL;
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType8(uint64_t Imm)
{
	return (Imm & 0x00ff0000ULL) >> 16;
}

// abcdefgh abcdefgh abcdefgh abcdefgh abcdefgh abcdefgh abcdefgh abcdefgh
static inline bool AArch64_AM_isAdvSIMDModImmType9(uint64_t Imm)
{
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       ((Imm >> 48) == (Imm & 0x0000ffffULL)) &&
	       ((Imm >> 56) == (Imm & 0x000000ffULL));
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType9(uint64_t Imm)
{
	return (Imm & 0xffULL);
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType9(uint8_t Imm)
{
	uint64_t EncVal = Imm;
	EncVal |= (EncVal << 8);
	EncVal |= (EncVal << 16);
	EncVal |= (EncVal << 32);
	return EncVal;
}

// aaaaaaaa bbbbbbbb cccccccc dddddddd eeeeeeee ffffffff gggggggg hhhhhhhh
// cmode: 1110, op: 1
static inline bool AArch64_AM_isAdvSIMDModImmType10(uint64_t Imm)
{
#if defined(_MSC_VER) && _MSC_VER == 1937 && !defined(__clang__) && \
	defined(_M_ARM64)
	// The MSVC compiler 19.37 for ARM64 has an optimization bug that
	// causes an incorrect behavior with the orignal version. Work around
	// by using a slightly different variation.
	// https://developercommunity.visualstudio.com/t/C-ARM64-compiler-optimization-bug/10481261
	constexpr uint64_t Mask = 0xFFULL;
	uint64_t ByteA = (Imm >> 56) & Mask;
	uint64_t ByteB = (Imm >> 48) & Mask;
	uint64_t ByteC = (Imm >> 40) & Mask;
	uint64_t ByteD = (Imm >> 32) & Mask;
	uint64_t ByteE = (Imm >> 24) & Mask;
	uint64_t ByteF = (Imm >> 16) & Mask;
	uint64_t ByteG = (Imm >> 8) & Mask;
	uint64_t ByteH = Imm & Mask;

	return (ByteA == 0ULL || ByteA == Mask) &&
	       (ByteB == 0ULL || ByteB == Mask) &&
	       (ByteC == 0ULL || ByteC == Mask) &&
	       (ByteD == 0ULL || ByteD == Mask) &&
	       (ByteE == 0ULL || ByteE == Mask) &&
	       (ByteF == 0ULL || ByteF == Mask) &&
	       (ByteG == 0ULL || ByteG == Mask) &&
	       (ByteH == 0ULL || ByteH == Mask);
#else
	uint64_t ByteA = Imm & 0xff00000000000000ULL;
	uint64_t ByteB = Imm & 0x00ff000000000000ULL;
	uint64_t ByteC = Imm & 0x0000ff0000000000ULL;
	uint64_t ByteD = Imm & 0x000000ff00000000ULL;
	uint64_t ByteE = Imm & 0x00000000ff000000ULL;
	uint64_t ByteF = Imm & 0x0000000000ff0000ULL;
	uint64_t ByteG = Imm & 0x000000000000ff00ULL;
	uint64_t ByteH = Imm & 0x00000000000000ffULL;

	return (ByteA == 0ULL || ByteA == 0xff00000000000000ULL) &&
	       (ByteB == 0ULL || ByteB == 0x00ff000000000000ULL) &&
	       (ByteC == 0ULL || ByteC == 0x0000ff0000000000ULL) &&
	       (ByteD == 0ULL || ByteD == 0x000000ff00000000ULL) &&
	       (ByteE == 0ULL || ByteE == 0x00000000ff000000ULL) &&
	       (ByteF == 0ULL || ByteF == 0x0000000000ff0000ULL) &&
	       (ByteG == 0ULL || ByteG == 0x000000000000ff00ULL) &&
	       (ByteH == 0ULL || ByteH == 0x00000000000000ffULL);
#endif
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType10(uint64_t Imm)
{
	uint8_t BitA = (Imm & 0xff00000000000000ULL) != 0;
	uint8_t BitB = (Imm & 0x00ff000000000000ULL) != 0;
	uint8_t BitC = (Imm & 0x0000ff0000000000ULL) != 0;
	uint8_t BitD = (Imm & 0x000000ff00000000ULL) != 0;
	uint8_t BitE = (Imm & 0x00000000ff000000ULL) != 0;
	uint8_t BitF = (Imm & 0x0000000000ff0000ULL) != 0;
	uint8_t BitG = (Imm & 0x000000000000ff00ULL) != 0;
	uint8_t BitH = (Imm & 0x00000000000000ffULL) != 0;

	uint8_t EncVal = BitA;
	EncVal <<= 1;
	EncVal |= BitB;
	EncVal <<= 1;
	EncVal |= BitC;
	EncVal <<= 1;
	EncVal |= BitD;
	EncVal <<= 1;
	EncVal |= BitE;
	EncVal <<= 1;
	EncVal |= BitF;
	EncVal <<= 1;
	EncVal |= BitG;
	EncVal <<= 1;
	EncVal |= BitH;
	return EncVal;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType10(uint8_t Imm)
{
	uint64_t EncVal = 0;
	if (Imm & 0x80)
		EncVal |= 0xff00000000000000ULL;
	if (Imm & 0x40)
		EncVal |= 0x00ff000000000000ULL;
	if (Imm & 0x20)
		EncVal |= 0x0000ff0000000000ULL;
	if (Imm & 0x10)
		EncVal |= 0x000000ff00000000ULL;
	if (Imm & 0x08)
		EncVal |= 0x00000000ff000000ULL;
	if (Imm & 0x04)
		EncVal |= 0x0000000000ff0000ULL;
	if (Imm & 0x02)
		EncVal |= 0x000000000000ff00ULL;
	if (Imm & 0x01)
		EncVal |= 0x00000000000000ffULL;
	return EncVal;
}

// aBbbbbbc defgh000 0x00 0x00 aBbbbbbc defgh000 0x00 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType11(uint64_t Imm)
{
	uint64_t BString = (Imm & 0x7E000000ULL) >> 25;
	return ((Imm >> 32) == (Imm & 0xffffffffULL)) &&
	       (BString == 0x1f || BString == 0x20) &&
	       ((Imm & 0x0007ffff0007ffffULL) == 0);
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType11(uint64_t Imm)
{
	uint8_t BitA = (Imm & 0x80000000ULL) != 0;
	uint8_t BitB = (Imm & 0x20000000ULL) != 0;
	uint8_t BitC = (Imm & 0x01000000ULL) != 0;
	uint8_t BitD = (Imm & 0x00800000ULL) != 0;
	uint8_t BitE = (Imm & 0x00400000ULL) != 0;
	uint8_t BitF = (Imm & 0x00200000ULL) != 0;
	uint8_t BitG = (Imm & 0x00100000ULL) != 0;
	uint8_t BitH = (Imm & 0x00080000ULL) != 0;

	uint8_t EncVal = BitA;
	EncVal <<= 1;
	EncVal |= BitB;
	EncVal <<= 1;
	EncVal |= BitC;
	EncVal <<= 1;
	EncVal |= BitD;
	EncVal <<= 1;
	EncVal |= BitE;
	EncVal <<= 1;
	EncVal |= BitF;
	EncVal <<= 1;
	EncVal |= BitG;
	EncVal <<= 1;
	EncVal |= BitH;
	return EncVal;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType11(uint8_t Imm)
{
	uint64_t EncVal = 0;
	if (Imm & 0x80)
		EncVal |= 0x80000000ULL;
	if (Imm & 0x40)
		EncVal |= 0x3e000000ULL;
	else
		EncVal |= 0x40000000ULL;
	if (Imm & 0x20)
		EncVal |= 0x01000000ULL;
	if (Imm & 0x10)
		EncVal |= 0x00800000ULL;
	if (Imm & 0x08)
		EncVal |= 0x00400000ULL;
	if (Imm & 0x04)
		EncVal |= 0x00200000ULL;
	if (Imm & 0x02)
		EncVal |= 0x00100000ULL;
	if (Imm & 0x01)
		EncVal |= 0x00080000ULL;
	return (EncVal << 32) | EncVal;
}

// aBbbbbbb bbcdefgh 0x00 0x00 0x00 0x00 0x00 0x00
static inline bool AArch64_AM_isAdvSIMDModImmType12(uint64_t Imm)
{
	uint64_t BString = (Imm & 0x7fc0000000000000ULL) >> 54;
	return ((BString == 0xff || BString == 0x100) &&
		((Imm & 0x0000ffffffffffffULL) == 0));
}

static inline uint8_t AArch64_AM_encodeAdvSIMDModImmType12(uint64_t Imm)
{
	uint8_t BitA = (Imm & 0x8000000000000000ULL) != 0;
	uint8_t BitB = (Imm & 0x0040000000000000ULL) != 0;
	uint8_t BitC = (Imm & 0x0020000000000000ULL) != 0;
	uint8_t BitD = (Imm & 0x0010000000000000ULL) != 0;
	uint8_t BitE = (Imm & 0x0008000000000000ULL) != 0;
	uint8_t BitF = (Imm & 0x0004000000000000ULL) != 0;
	uint8_t BitG = (Imm & 0x0002000000000000ULL) != 0;
	uint8_t BitH = (Imm & 0x0001000000000000ULL) != 0;

	uint8_t EncVal = BitA;
	EncVal <<= 1;
	EncVal |= BitB;
	EncVal <<= 1;
	EncVal |= BitC;
	EncVal <<= 1;
	EncVal |= BitD;
	EncVal <<= 1;
	EncVal |= BitE;
	EncVal <<= 1;
	EncVal |= BitF;
	EncVal <<= 1;
	EncVal |= BitG;
	EncVal <<= 1;
	EncVal |= BitH;
	return EncVal;
}

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType12(uint8_t Imm)
{
	uint64_t EncVal = 0;
	if (Imm & 0x80)
		EncVal |= 0x8000000000000000ULL;
	if (Imm & 0x40)
		EncVal |= 0x3fc0000000000000ULL;
	else
		EncVal |= 0x4000000000000000ULL;
	if (Imm & 0x20)
		EncVal |= 0x0020000000000000ULL;
	if (Imm & 0x10)
		EncVal |= 0x0010000000000000ULL;
	if (Imm & 0x08)
		EncVal |= 0x0008000000000000ULL;
	if (Imm & 0x04)
		EncVal |= 0x0004000000000000ULL;
	if (Imm & 0x02)
		EncVal |= 0x0002000000000000ULL;
	if (Imm & 0x01)
		EncVal |= 0x0001000000000000ULL;
	return (EncVal << 32) | EncVal;
}

/// Returns true if Imm is the concatenation of a repeating pattern of type T.
#define DEFINE_isSVEMaskOfIdenticalElements(T) \
	static inline bool CONCAT(AArch64_AM_isSVEMaskOfIdenticalElements, \
				  T)(int64_t Imm) \
	{ \
		union { \
			int64_t In; \
			T Out[sizeof(int64_t) / sizeof(T)]; \
		} U_Parts; \
		U_Parts.In = Imm; \
		T *Parts = U_Parts.Out; \
		for (int i = 0; i < (sizeof(int64_t) / sizeof(T)); i++) { \
			if (Parts[i] != Parts[0]) \
				return false; \
		} \
		return true; \
	}
DEFINE_isSVEMaskOfIdenticalElements(int8_t);
DEFINE_isSVEMaskOfIdenticalElements(int16_t);
DEFINE_isSVEMaskOfIdenticalElements(int32_t);
DEFINE_isSVEMaskOfIdenticalElements(int64_t);

static inline bool isSVECpyImm8(int64_t Imm)
{
	bool IsImm8 = (int8_t)Imm == Imm;

	return IsImm8 || (uint8_t)Imm == Imm;
}

static inline bool isSVECpyImm16(int64_t Imm)
{
	bool IsImm8 = (int8_t)Imm == Imm;
	bool IsImm16 = (int16_t)(Imm & ~0xff) == Imm;

	return IsImm8 || IsImm16 || (uint16_t)(Imm & ~0xff) == Imm;
}

static inline bool isSVECpyImm32(int64_t Imm)
{
	bool IsImm8 = (int8_t)Imm == Imm;
	bool IsImm16 = (int16_t)(Imm & ~0xff) == Imm;

	return IsImm8 || IsImm16;
}

static inline bool isSVECpyImm64(int64_t Imm)
{
	bool IsImm8 = (int8_t)Imm == Imm;
	bool IsImm16 = (int16_t)(Imm & ~0xff) == Imm;

	return IsImm8 || IsImm16;
}

/// Return true if Imm is valid for DUPM and has no single CPY/DUP equivalent.
static inline bool
AArch64_AM_isSVEMoveMaskPreferredLogicalImmediate(int64_t Imm)
{
	if (isSVECpyImm64(Imm))
		return false;

	union {
		int64_t In;
		int32_t Out[2];
	} U_S;
	U_S.In = Imm;
	int32_t *S = U_S.Out;
	union {
		int64_t In;
		int16_t Out[4];
	} U_H;
	U_H.In = Imm;
	int16_t *H = U_H.Out;
	union {
		int64_t In;
		int8_t Out[8];
	} U_B;
	U_B.In = Imm;
	int8_t *B = U_B.Out;

	if (CONCAT(AArch64_AM_isSVEMaskOfIdenticalElements, int32_t)(Imm) &&
	    isSVECpyImm32(S[0]))
		return false;
	if (CONCAT(AArch64_AM_isSVEMaskOfIdenticalElements, int16_t)(Imm) &&
	    isSVECpyImm16(H[0]))
		return false;
	if (CONCAT(AArch64_AM_isSVEMaskOfIdenticalElements, int8_t)(Imm) &&
	    isSVECpyImm8(B[0]))
		return false;
	return AArch64_AM_isLogicalImmediate(Imm, 64);
}

inline static bool AArch64_AM_isAnyMOVZMovAlias(uint64_t Value, int RegWidth)
{
	for (int Shift = 0; Shift <= RegWidth - 16; Shift += 16)
		if ((Value & ~(0xffffULL << Shift)) == 0)
			return true;

	return false;
}

inline static bool AArch64_AM_isMOVZMovAlias(uint64_t Value, int Shift,
					     int RegWidth)
{
	if (RegWidth == 32)
		Value &= 0xffffffffULL;

	// "lsl #0" takes precedence: in practice this only affects "#0, lsl #0".
	if (Value == 0 && Shift != 0)
		return false;

	return (Value & ~(0xffffULL << Shift)) == 0;
}

inline static bool AArch64_AM_isMOVNMovAlias(uint64_t Value, int Shift,
					     int RegWidth)
{
	// MOVZ takes precedence over MOVN.
	if (AArch64_AM_isAnyMOVZMovAlias(Value, RegWidth))
		return false;

	Value = ~Value;
	if (RegWidth == 32)
		Value &= 0xffffffffULL;

	return AArch64_AM_isMOVZMovAlias(Value, Shift, RegWidth);
}

inline static bool AArch64_AM_isAnyMOVWMovAlias(uint64_t Value, int RegWidth)
{
	if (AArch64_AM_isAnyMOVZMovAlias(Value, RegWidth))
		return true;

	// It's not a MOVZ, but it might be a MOVN.
	Value = ~Value;
	if (RegWidth == 32)
		Value &= 0xffffffffULL;

	return AArch64_AM_isAnyMOVZMovAlias(Value, RegWidth);
}

// CS namespace end: AArch64_AM

// end namespace AArch64_AM

// end namespace llvm

#endif
