//===- AArch64AddressingModes.h - AArch64 Addressing Modes ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the AArch64 addressing mode implementation stuff.
//
//===----------------------------------------------------------------------===//

#ifndef CS_AARCH64_ADDRESSINGMODES_H
#define CS_AARCH64_ADDRESSINGMODES_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */

#include "../../MathExtras.h"

/// AArch64_AM - AArch64 Addressing Mode Stuff

//===----------------------------------------------------------------------===//
// Shifts
//

typedef enum AArch64_AM_ShiftExtendType {
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
static inline const char *AArch64_AM_getShiftExtendName(AArch64_AM_ShiftExtendType ST)
{
	switch (ST) {
		default: return NULL; // never reach
		case AArch64_AM_LSL: return "lsl";
		case AArch64_AM_LSR: return "lsr";
		case AArch64_AM_ASR: return "asr";
		case AArch64_AM_ROR: return "ror";
		case AArch64_AM_MSL: return "msl";
		case AArch64_AM_UXTB: return "uxtb";
		case AArch64_AM_UXTH: return "uxth";
		case AArch64_AM_UXTW: return "uxtw";
		case AArch64_AM_UXTX: return "uxtx";
		case AArch64_AM_SXTB: return "sxtb";
		case AArch64_AM_SXTH: return "sxth";
		case AArch64_AM_SXTW: return "sxtw";
		case AArch64_AM_SXTX: return "sxtx";
	}
}

/// getShiftType - Extract the shift type.
static inline AArch64_AM_ShiftExtendType AArch64_AM_getShiftType(unsigned Imm)
{
	switch ((Imm >> 6) & 0x7) {
		default: return AArch64_AM_InvalidShiftExtend;
		case 0: return AArch64_AM_LSL;
		case 1: return AArch64_AM_LSR;
		case 2: return AArch64_AM_ASR;
		case 3: return AArch64_AM_ROR;
		case 4: return AArch64_AM_MSL;
	}
}

/// getShiftValue - Extract the shift value.
static inline unsigned AArch64_AM_getShiftValue(unsigned Imm)
{
	return Imm & 0x3f;
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
	// assert((Imm & 0x7) == Imm && "invalid immediate!");
	switch (Imm) {
		default: // llvm_unreachable("Compiler bug!");
		case 0: return AArch64_AM_UXTB;
		case 1: return AArch64_AM_UXTH;
		case 2: return AArch64_AM_UXTW;
		case 3: return AArch64_AM_UXTX;
		case 4: return AArch64_AM_SXTB;
		case 5: return AArch64_AM_SXTH;
		case 6: return AArch64_AM_SXTW;
		case 7: return AArch64_AM_SXTX;
	}
}

static inline AArch64_AM_ShiftExtendType AArch64_AM_getArithExtendType(unsigned Imm)
{
	return AArch64_AM_getExtendType((Imm >> 3) & 0x7);
}

static inline uint64_t ror(uint64_t elt, unsigned size)
{
	return ((elt & 1) << (size-1)) | (elt >> 1);
}

/// decodeLogicalImmediate - Decode a logical immediate value in the form
/// "N:immr:imms" (where the immr and imms fields are each 6 bits) into the
/// integer value it represents with regSize bits.
static inline uint64_t AArch64_AM_decodeLogicalImmediate(uint64_t val, unsigned regSize)
{
	// Extract the N, imms, and immr fields.
	unsigned N = (val >> 12) & 1;
	unsigned immr = (val >> 6) & 0x3f;
	unsigned imms = val & 0x3f;
	unsigned i;

	// assert((regSize == 64 || N == 0) && "undefined logical immediate encoding");
	int len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
	// assert(len >= 0 && "undefined logical immediate encoding");
	unsigned size = (1 << len);
	unsigned R = immr & (size - 1);
	unsigned S = imms & (size - 1);
	// assert(S != size - 1 && "undefined logical immediate encoding");
	uint64_t pattern = (1ULL << (S + 1)) - 1;
	for (i = 0; i < R; ++i)
		pattern = ror(pattern, size);

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
static inline bool AArch64_AM_isValidDecodeLogicalImmediate(uint64_t val, unsigned regSize)
{
	unsigned size;
	unsigned S;
	int len;
	// Extract the N and imms fields needed for checking.
	unsigned N = (val >> 12) & 1;
	unsigned imms = val & 0x3f;

	if (regSize == 32 && N != 0) // undefined logical immediate encoding
		return false;
	len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
	if (len < 0) // undefined logical immediate encoding
		return false;
	size = (1 << len);
	S = imms & (size - 1);
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
	union {
		uint32_t I;
		float F;
	} FPUnion;

	uint8_t Sign = (Imm >> 7) & 0x1;
	uint8_t Exp = (Imm >> 4) & 0x7;
	uint8_t Mantissa = Imm & 0xf;

	//   8-bit FP    iEEEE Float Encoding
	//   abcd efgh   aBbbbbbc defgh000 00000000 00000000
	//
	// where B = NOT(b);

	FPUnion.I = 0;
	FPUnion.I |= Sign << 31;
	FPUnion.I |= ((Exp & 0x4) != 0 ? 0 : 1) << 30;
	FPUnion.I |= ((Exp & 0x4) != 0 ? 0x1f : 0) << 25;
	FPUnion.I |= (Exp & 0x3) << 23;
	FPUnion.I |= Mantissa << 19;

	return FPUnion.F;
}

//===--------------------------------------------------------------------===//
// AdvSIMD Modified Immediates
//===--------------------------------------------------------------------===//

static inline uint64_t AArch64_AM_decodeAdvSIMDModImmType10(uint8_t Imm)
{
	static const uint64_t lookup[256] = {
		0x0000000000000000, 0x00000000000000ff, 0x000000000000ff00, 0x000000000000ffff, 
		0x0000000000ff0000, 0x0000000000ff00ff, 0x0000000000ffff00, 0x0000000000ffffff, 
		0x00000000ff000000, 0x00000000ff0000ff, 0x00000000ff00ff00, 0x00000000ff00ffff, 
		0x00000000ffff0000, 0x00000000ffff00ff, 0x00000000ffffff00, 0x00000000ffffffff, 
		0x000000ff00000000, 0x000000ff000000ff, 0x000000ff0000ff00, 0x000000ff0000ffff, 
		0x000000ff00ff0000, 0x000000ff00ff00ff, 0x000000ff00ffff00, 0x000000ff00ffffff, 
		0x000000ffff000000, 0x000000ffff0000ff, 0x000000ffff00ff00, 0x000000ffff00ffff, 
		0x000000ffffff0000, 0x000000ffffff00ff, 0x000000ffffffff00, 0x000000ffffffffff, 
		0x0000ff0000000000, 0x0000ff00000000ff, 0x0000ff000000ff00, 0x0000ff000000ffff, 
		0x0000ff0000ff0000, 0x0000ff0000ff00ff, 0x0000ff0000ffff00, 0x0000ff0000ffffff, 
		0x0000ff00ff000000, 0x0000ff00ff0000ff, 0x0000ff00ff00ff00, 0x0000ff00ff00ffff, 
		0x0000ff00ffff0000, 0x0000ff00ffff00ff, 0x0000ff00ffffff00, 0x0000ff00ffffffff, 
		0x0000ffff00000000, 0x0000ffff000000ff, 0x0000ffff0000ff00, 0x0000ffff0000ffff, 
		0x0000ffff00ff0000, 0x0000ffff00ff00ff, 0x0000ffff00ffff00, 0x0000ffff00ffffff, 
		0x0000ffffff000000, 0x0000ffffff0000ff, 0x0000ffffff00ff00, 0x0000ffffff00ffff, 
		0x0000ffffffff0000, 0x0000ffffffff00ff, 0x0000ffffffffff00, 0x0000ffffffffffff, 
		0x00ff000000000000, 0x00ff0000000000ff, 0x00ff00000000ff00, 0x00ff00000000ffff, 
		0x00ff000000ff0000, 0x00ff000000ff00ff, 0x00ff000000ffff00, 0x00ff000000ffffff, 
		0x00ff0000ff000000, 0x00ff0000ff0000ff, 0x00ff0000ff00ff00, 0x00ff0000ff00ffff, 
		0x00ff0000ffff0000, 0x00ff0000ffff00ff, 0x00ff0000ffffff00, 0x00ff0000ffffffff, 
		0x00ff00ff00000000, 0x00ff00ff000000ff, 0x00ff00ff0000ff00, 0x00ff00ff0000ffff, 
		0x00ff00ff00ff0000, 0x00ff00ff00ff00ff, 0x00ff00ff00ffff00, 0x00ff00ff00ffffff, 
		0x00ff00ffff000000, 0x00ff00ffff0000ff, 0x00ff00ffff00ff00, 0x00ff00ffff00ffff, 
		0x00ff00ffffff0000, 0x00ff00ffffff00ff, 0x00ff00ffffffff00, 0x00ff00ffffffffff, 
		0x00ffff0000000000, 0x00ffff00000000ff, 0x00ffff000000ff00, 0x00ffff000000ffff, 
		0x00ffff0000ff0000, 0x00ffff0000ff00ff, 0x00ffff0000ffff00, 0x00ffff0000ffffff, 
		0x00ffff00ff000000, 0x00ffff00ff0000ff, 0x00ffff00ff00ff00, 0x00ffff00ff00ffff, 
		0x00ffff00ffff0000, 0x00ffff00ffff00ff, 0x00ffff00ffffff00, 0x00ffff00ffffffff, 
		0x00ffffff00000000, 0x00ffffff000000ff, 0x00ffffff0000ff00, 0x00ffffff0000ffff, 
		0x00ffffff00ff0000, 0x00ffffff00ff00ff, 0x00ffffff00ffff00, 0x00ffffff00ffffff, 
		0x00ffffffff000000, 0x00ffffffff0000ff, 0x00ffffffff00ff00, 0x00ffffffff00ffff, 
		0x00ffffffffff0000, 0x00ffffffffff00ff, 0x00ffffffffffff00, 0x00ffffffffffffff, 
		0xff00000000000000, 0xff000000000000ff, 0xff0000000000ff00, 0xff0000000000ffff, 
		0xff00000000ff0000, 0xff00000000ff00ff, 0xff00000000ffff00, 0xff00000000ffffff, 
		0xff000000ff000000, 0xff000000ff0000ff, 0xff000000ff00ff00, 0xff000000ff00ffff, 
		0xff000000ffff0000, 0xff000000ffff00ff, 0xff000000ffffff00, 0xff000000ffffffff, 
		0xff0000ff00000000, 0xff0000ff000000ff, 0xff0000ff0000ff00, 0xff0000ff0000ffff, 
		0xff0000ff00ff0000, 0xff0000ff00ff00ff, 0xff0000ff00ffff00, 0xff0000ff00ffffff, 
		0xff0000ffff000000, 0xff0000ffff0000ff, 0xff0000ffff00ff00, 0xff0000ffff00ffff, 
		0xff0000ffffff0000, 0xff0000ffffff00ff, 0xff0000ffffffff00, 0xff0000ffffffffff, 
		0xff00ff0000000000, 0xff00ff00000000ff, 0xff00ff000000ff00, 0xff00ff000000ffff, 
		0xff00ff0000ff0000, 0xff00ff0000ff00ff, 0xff00ff0000ffff00, 0xff00ff0000ffffff, 
		0xff00ff00ff000000, 0xff00ff00ff0000ff, 0xff00ff00ff00ff00, 0xff00ff00ff00ffff, 
		0xff00ff00ffff0000, 0xff00ff00ffff00ff, 0xff00ff00ffffff00, 0xff00ff00ffffffff, 
		0xff00ffff00000000, 0xff00ffff000000ff, 0xff00ffff0000ff00, 0xff00ffff0000ffff, 
		0xff00ffff00ff0000, 0xff00ffff00ff00ff, 0xff00ffff00ffff00, 0xff00ffff00ffffff, 
		0xff00ffffff000000, 0xff00ffffff0000ff, 0xff00ffffff00ff00, 0xff00ffffff00ffff, 
		0xff00ffffffff0000, 0xff00ffffffff00ff, 0xff00ffffffffff00, 0xff00ffffffffffff, 
		0xffff000000000000, 0xffff0000000000ff, 0xffff00000000ff00, 0xffff00000000ffff, 
		0xffff000000ff0000, 0xffff000000ff00ff, 0xffff000000ffff00, 0xffff000000ffffff, 
		0xffff0000ff000000, 0xffff0000ff0000ff, 0xffff0000ff00ff00, 0xffff0000ff00ffff, 
		0xffff0000ffff0000, 0xffff0000ffff00ff, 0xffff0000ffffff00, 0xffff0000ffffffff, 
		0xffff00ff00000000, 0xffff00ff000000ff, 0xffff00ff0000ff00, 0xffff00ff0000ffff, 
		0xffff00ff00ff0000, 0xffff00ff00ff00ff, 0xffff00ff00ffff00, 0xffff00ff00ffffff, 
		0xffff00ffff000000, 0xffff00ffff0000ff, 0xffff00ffff00ff00, 0xffff00ffff00ffff, 
		0xffff00ffffff0000, 0xffff00ffffff00ff, 0xffff00ffffffff00, 0xffff00ffffffffff, 
		0xffffff0000000000, 0xffffff00000000ff, 0xffffff000000ff00, 0xffffff000000ffff, 
		0xffffff0000ff0000, 0xffffff0000ff00ff, 0xffffff0000ffff00, 0xffffff0000ffffff, 
		0xffffff00ff000000, 0xffffff00ff0000ff, 0xffffff00ff00ff00, 0xffffff00ff00ffff, 
		0xffffff00ffff0000, 0xffffff00ffff00ff, 0xffffff00ffffff00, 0xffffff00ffffffff, 
		0xffffffff00000000, 0xffffffff000000ff, 0xffffffff0000ff00, 0xffffffff0000ffff, 
		0xffffffff00ff0000, 0xffffffff00ff00ff, 0xffffffff00ffff00, 0xffffffff00ffffff, 
		0xffffffffff000000, 0xffffffffff0000ff, 0xffffffffff00ff00, 0xffffffffff00ffff, 
		0xffffffffffff0000, 0xffffffffffff00ff, 0xffffffffffffff00, 0xffffffffffffffff
	};
	return lookup[Imm];
}

#endif
