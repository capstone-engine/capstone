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

//===-- ARMAddressingModes.h - ARM Addressing Modes -------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the ARM addressing mode implementation stuff.
//
//===----------------------------------------------------------------------===//

#ifndef CS_ARM_ADDRESSINGMODES_H
#define CS_ARM_ADDRESSINGMODES_H

#include "../../cs_priv.h"
#include <capstone/platform.h>

#include <assert.h>
#include "../../MathExtras.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

/// ARM_AM - ARM Addressing Mode Stuff
// CS namespace begin: ARM_AM

typedef enum ShiftOpc {
	ARM_AM_no_shift = 0,
	ARM_AM_asr,
	ARM_AM_lsl,
	ARM_AM_lsr,
	ARM_AM_ror,
	ARM_AM_rrx,
	ARM_AM_uxtw
} ARM_AM_ShiftOpc;

typedef enum AddrOpc { ARM_AM_sub = 0, ARM_AM_add } ARM_AM_AddrOpc;

static inline const char *ARM_AM_getAddrOpcStr(ARM_AM_AddrOpc Op)
{
	return Op == ARM_AM_sub ? "-" : "";
}

static inline const char *ARM_AM_getShiftOpcStr(ARM_AM_ShiftOpc Op)
{
	switch (Op) {
	default:
		CS_ASSERT_RET_VAL(0 && "Unknown shift opc!", NULL);
	case ARM_AM_asr:
		return "asr";
	case ARM_AM_lsl:
		return "lsl";
	case ARM_AM_lsr:
		return "lsr";
	case ARM_AM_ror:
		return "ror";
	case ARM_AM_rrx:
		return "rrx";
	case ARM_AM_uxtw:
		return "uxtw";
	}
}

static inline unsigned ARM_AM_getShiftOpcEncoding(ARM_AM_ShiftOpc Op)
{
	switch (Op) {
	default:
		CS_ASSERT_RET_VAL(0 && "Unknown shift opc!", 0);
	case ARM_AM_asr:
		return 2;
	case ARM_AM_lsl:
		return 0;
	case ARM_AM_lsr:
		return 1;
	case ARM_AM_ror:
		return 3;
	}
}

typedef enum AMSubMode {
	ARM_AM_bad_am_submode = 0,
	ARM_AM_ia,
	ARM_AM_ib,
	ARM_AM_da,
	ARM_AM_db
} ARM_AM_SubMode;

static inline const char *ARM_AM_getAMSubModeStr(ARM_AM_SubMode Mode)
{
	switch (Mode) {
	default:
		CS_ASSERT_RET_VAL(0 && "Unknown addressing sub-mode!", NULL);
	case ARM_AM_ia:
		return "ia";
	case ARM_AM_ib:
		return "ib";
	case ARM_AM_da:
		return "da";
	case ARM_AM_db:
		return "db";
	}
}

//===--------------------------------------------------------------------===//
// Addressing Mode #1: shift_operand with registers
//===--------------------------------------------------------------------===//
//
// This 'addressing mode' is used for arithmetic instructions.  It can
// represent things like:
//   reg
//   reg [asr|lsl|lsr|ror|rrx] reg
//   reg [asr|lsl|lsr|ror|rrx] imm
//
// This is stored three operands [rega, regb, opc].  The first is the base
// reg, the second is the shift amount (or reg0 if not present or imm).  The
// third operand encodes the shift opcode and the imm if a reg isn't present.
static inline unsigned ARM_AM_rotr32(unsigned Val, unsigned Amt)
{
	CS_ASSERT(Amt <= 32);
	if (Amt == 32) {
		return Val;
	}
	return (Val >> Amt) |
	       (Val << ((32 - Amt) &
			31)); // NOLINT(clang-analyzer-core.BitwiseShift)
}

static inline unsigned ARM_AM_rotl32(unsigned Val, unsigned Amt)
{
	return (Val << Amt) | (Val >> ((32 - Amt) & 31));
}

static inline unsigned ARM_AM_getSORegOpc(ARM_AM_ShiftOpc ShOp, unsigned Imm)
{
	return ShOp | (Imm << 3);
}

static inline unsigned ARM_AM_getSORegOffset(unsigned Op)
{
	return Op >> 3;
}

static inline ARM_AM_ShiftOpc ARM_AM_getSORegShOp(unsigned Op)
{
	return (ARM_AM_ShiftOpc)(Op & 7);
}

/// getSOImmValImm - Given an encoded imm field for the reg/imm form, return
/// the 8-bit imm value.
static inline unsigned ARM_AM_getSOImmValImm(unsigned Imm)
{
	return Imm & 0xFF;
}

/// getSOImmValRot - Given an encoded imm field for the reg/imm form, return
/// the rotate amount.
static inline unsigned ARM_AM_getSOImmValRot(unsigned Imm)
{
	return (Imm >> 8) * 2;
}

/// getSOImmValRotate - Try to handle Imm with an immediate shifter operand,
/// computing the rotate amount to use.  If this immediate value cannot be
/// handled with a single shifter-op, determine a good rotate amount that will
/// take a maximal chunk of bits out of the immediate.
static inline unsigned ARM_AM_getSOImmValRotate(unsigned Imm)
{
	// 8-bit (or less) immediates are trivially shifter_operands with a rotate
	// of zero.
	if ((Imm & ~255U) == 0)
		return 0;

	// Use CTZ to compute the rotate amount.
	unsigned TZ = CountTrailingZeros_32(Imm);

	// Rotate amount must be even.  Something like 0x200 must be rotated 8 bits,
	// not 9.
	unsigned RotAmt = TZ & ~1;

	// If we can handle this spread, return it.
	if ((ARM_AM_rotr32(Imm, RotAmt) & ~255U) == 0)
		return (32 - RotAmt) & 31; // HW rotates right, not left.

	// For values like 0xF000000F, we should ignore the low 6 bits, then
	// retry the hunt.
	if (Imm & 63U) {
		unsigned TZ2 = CountTrailingZeros_32(Imm & ~63U);
		unsigned RotAmt2 = TZ2 & ~1;
		if ((ARM_AM_rotr32(Imm, RotAmt2) & ~255U) == 0)
			return (32 - RotAmt2) &
			       31; // HW rotates right, not left.
	}

	// Otherwise, we have no way to cover this span of bits with a single
	// shifter_op immediate.  Return a chunk of bits that will be useful to
	// handle.
	return (32 - RotAmt) & 31; // HW rotates right, not left.
}

/// getSOImmVal - Given a 32-bit immediate, if it is something that can fit
/// into an shifter_operand immediate operand, return the 12-bit encoding for
/// it.  If not, return -1.
static inline int ARM_AM_getSOImmVal(unsigned Arg)
{
	// 8-bit (or less) immediates are trivially shifter_operands with a rotate
	// of zero.
	if ((Arg & ~255U) == 0)
		return Arg;

	unsigned RotAmt = ARM_AM_getSOImmValRotate(Arg);

	// If this cannot be handled with a single shifter_op, bail out.
	if (ARM_AM_rotr32(~255U, RotAmt) & Arg)
		return -1;

	// Encode this correctly.
	return ARM_AM_rotl32(Arg, RotAmt) | ((RotAmt >> 1) << 8);
}

/// isSOImmTwoPartVal - Return true if the specified value can be obtained by
/// or'ing together two SOImmVal's.
static inline bool ARM_AM_isSOImmTwoPartVal(unsigned V)
{
	// If this can be handled with a single shifter_op, bail out.
	V = ARM_AM_rotr32(~255U, ARM_AM_getSOImmValRotate(V)) & V;
	if (V == 0)
		return false;

	// If this can be handled with two shifter_op's, accept.
	V = ARM_AM_rotr32(~255U, ARM_AM_getSOImmValRotate(V)) & V;
	return V == 0;
}

/// getSOImmTwoPartFirst - If V is a value that satisfies isSOImmTwoPartVal,
/// return the first chunk of it.
static inline unsigned ARM_AM_getSOImmTwoPartFirst(unsigned V)
{
	return ARM_AM_rotr32(255U, ARM_AM_getSOImmValRotate(V)) & V;
}

/// getSOImmTwoPartSecond - If V is a value that satisfies isSOImmTwoPartVal,
/// return the second chunk of it.
static inline unsigned ARM_AM_getSOImmTwoPartSecond(unsigned V)
{
	// Mask out the first hunk.
	V = ARM_AM_rotr32(~255U, ARM_AM_getSOImmValRotate(V)) & V;

	// Take what's left.

	return V;
}

/// isSOImmTwoPartValNeg - Return true if the specified value can be obtained
/// by two SOImmVal, that -V = First + Second.
/// "R+V" can be optimized to (sub (sub R, First), Second).
/// "R=V" can be optimized to (sub (mvn R, ~(-First)), Second).
static inline bool ARM_AM_isSOImmTwoPartValNeg(unsigned V)
{
	unsigned First;
	if (!ARM_AM_isSOImmTwoPartVal(-V))
		return false;
	// Return false if ~(-First) is not a SoImmval.
	First = ARM_AM_getSOImmTwoPartFirst(-V);
	First = ~(-First);
	return !(ARM_AM_rotr32(~255U, ARM_AM_getSOImmValRotate(First)) & First);
}

/// getThumbImmValShift - Try to handle Imm with a 8-bit immediate followed
/// by a left shift. Returns the shift amount to use.
static inline unsigned ARM_AM_getThumbImmValShift(unsigned Imm)
{
	// 8-bit (or less) immediates are trivially immediate operand with a shift
	// of zero.
	if ((Imm & ~255U) == 0)
		return 0;

	// Use CTZ to compute the shift amount.
	return CountTrailingZeros_32(Imm);
}

/// isThumbImmShiftedVal - Return true if the specified value can be obtained
/// by left shifting a 8-bit immediate.
static inline bool ARM_AM_isThumbImmShiftedVal(unsigned V)
{
	// If this can be handled with
	V = (~255U << ARM_AM_getThumbImmValShift(V)) & V;
	return V == 0;
}

/// getThumbImm16ValShift - Try to handle Imm with a 16-bit immediate followed
/// by a left shift. Returns the shift amount to use.
static inline unsigned ARM_AM_getThumbImm16ValShift(unsigned Imm)
{
	// 16-bit (or less) immediates are trivially immediate operand with a shift
	// of zero.
	if ((Imm & ~65535U) == 0)
		return 0;

	// Use CTZ to compute the shift amount.
	return CountTrailingZeros_32(Imm);
}

/// isThumbImm16ShiftedVal - Return true if the specified value can be
/// obtained by left shifting a 16-bit immediate.
static inline bool ARM_AM_isThumbImm16ShiftedVal(unsigned V)
{
	// If this can be handled with
	V = (~65535U << ARM_AM_getThumbImm16ValShift(V)) & V;
	return V == 0;
}

/// getThumbImmNonShiftedVal - If V is a value that satisfies
/// isThumbImmShiftedVal, return the non-shiftd value.
static inline unsigned ARM_AM_getThumbImmNonShiftedVal(unsigned V)
{
	return V >> ARM_AM_getThumbImmValShift(V);
}

/// getT2SOImmValSplat - Return the 12-bit encoded representation
/// if the specified value can be obtained by splatting the low 8 bits
/// into every other byte or every byte of a 32-bit value. i.e.,
///     00000000 00000000 00000000 abcdefgh    control = 0
///     00000000 abcdefgh 00000000 abcdefgh    control = 1
///     abcdefgh 00000000 abcdefgh 00000000    control = 2
///     abcdefgh abcdefgh abcdefgh abcdefgh    control = 3
/// Return -1 if none of the above apply.
/// See ARM Reference Manual A6.3.2.
static inline int ARM_AM_getT2SOImmValSplatVal(unsigned V)
{
	unsigned u, Vs, Imm;
	// control = 0
	if ((V & 0xffffff00) == 0)
		return V;

	// If the value is zeroes in the first byte, just shift those off
	Vs = ((V & 0xff) == 0) ? V >> 8 : V;
	// Any passing value only has 8 bits of payload, splatted across the word
	Imm = Vs & 0xff;
	// Likewise, any passing values have the payload splatted into the 3rd byte
	u = Imm | (Imm << 16);

	// control = 1 or 2
	if (Vs == u)
		return (((Vs == V) ? 1 : 2) << 8) | Imm;

	// control = 3
	if (Vs == (u | (u << 8)))
		return (3 << 8) | Imm;

	return -1;
}

/// getT2SOImmValRotateVal - Return the 12-bit encoded representation if the
/// specified value is a rotated 8-bit value. Return -1 if no rotation
/// encoding is possible.
/// See ARM Reference Manual A6.3.2.
static inline int ARM_AM_getT2SOImmValRotateVal(unsigned V)
{
	unsigned RotAmt = CountLeadingZeros_32(V);
	if (RotAmt >= 24)
		return -1;

	// If 'Arg' can be handled with a single shifter_op return the value.
	if ((ARM_AM_rotr32(0xff000000U, RotAmt) & V) == V)
		return (ARM_AM_rotr32(V, 24 - RotAmt) & 0x7f) |
		       ((RotAmt + 8) << 7);

	return -1;
}

/// getT2SOImmVal - Given a 32-bit immediate, if it is something that can fit
/// into a Thumb-2 shifter_operand immediate operand, return the 12-bit
/// encoding for it.  If not, return -1.
/// See ARM Reference Manual A6.3.2.
static inline int ARM_AM_getT2SOImmVal(unsigned Arg)
{
	// If 'Arg' is an 8-bit splat, then get the encoded value.
	int Splat = ARM_AM_getT2SOImmValSplatVal(Arg);
	if (Splat != -1)
		return Splat;

	// If 'Arg' can be handled with a single shifter_op return the value.
	int Rot = ARM_AM_getT2SOImmValRotateVal(Arg);
	if (Rot != -1)
		return Rot;

	return -1;
}

static inline unsigned ARM_AM_getT2SOImmValRotate(unsigned V)
{
	if ((V & ~255U) == 0)
		return 0;
	// Use CTZ to compute the rotate amount.
	unsigned RotAmt = CountTrailingZeros_32(V);
	return (32 - RotAmt) & 31;
}

static inline bool ARM_AM_isT2SOImmTwoPartVal(unsigned Imm)
{
	unsigned V = Imm;
	// Passing values can be any combination of splat values and shifter
	// values. If this can be handled with a single shifter or splat, bail
	// out. Those should be handled directly, not with a two-part val.
	if (ARM_AM_getT2SOImmValSplatVal(V) != -1)
		return false;
	V = ARM_AM_rotr32(~255U, ARM_AM_getT2SOImmValRotate(V)) & V;
	if (V == 0)
		return false;

	// If this can be handled as an immediate, accept.
	if (ARM_AM_getT2SOImmVal(V) != -1)
		return true;

	// Likewise, try masking out a splat value first.
	V = Imm;
	if (ARM_AM_getT2SOImmValSplatVal(V & 0xff00ff00U) != -1)
		V &= ~0xff00ff00U;
	else if (ARM_AM_getT2SOImmValSplatVal(V & 0x00ff00ffU) != -1)
		V &= ~0x00ff00ffU;
	// If what's left can be handled as an immediate, accept.
	if (ARM_AM_getT2SOImmVal(V) != -1)
		return true;

	// Otherwise, do not accept.
	return false;
}

static inline unsigned ARM_AM_getT2SOImmTwoPartFirst(unsigned Imm)
{
	CS_ASSERT(ARM_AM_isT2SOImmTwoPartVal(Imm) &&
		  "Immedate cannot be encoded as two part immediate!");
	// Try a shifter operand as one part
	unsigned V = ARM_AM_rotr32(~255, ARM_AM_getT2SOImmValRotate(Imm)) & Imm;
	// If the rest is encodable as an immediate, then return it.
	if (ARM_AM_getT2SOImmVal(V) != -1)
		return V;

	// Try masking out a splat value first.
	if (ARM_AM_getT2SOImmValSplatVal(Imm & 0xff00ff00U) != -1)
		return Imm & 0xff00ff00U;

	// The other splat is all that's left as an option.
	CS_ASSERT(ARM_AM_getT2SOImmValSplatVal(Imm & 0x00ff00ffU) != -1);
	return Imm & 0x00ff00ffU;
}

static inline unsigned ARM_AM_getT2SOImmTwoPartSecond(unsigned Imm)
{
	// Mask out the first hunk
	Imm ^= ARM_AM_getT2SOImmTwoPartFirst(Imm);
	// Return what's left
	CS_ASSERT(ARM_AM_getT2SOImmVal(Imm) != -1 &&
		  "Unable to encode second part of T2 two part SO immediate");
	return Imm;
}

//===--------------------------------------------------------------------===//
// Addressing Mode #2
//===--------------------------------------------------------------------===//
//
// This is used for most simple load/store instructions.
//
// addrmode2 := reg +/- reg shop imm
// addrmode2 := reg +/- imm12
//
// The first operand is always a Reg.  The second operand is a reg if in
// reg/reg form, otherwise it's reg#0.  The third field encodes the operation
// in bit 12, the immediate in bits 0-11, and the shift op in 13-15. The
// fourth operand 16-17 encodes the index mode.
//
// If this addressing mode is a frame index (before prolog/epilog insertion
// and code rewriting), this operand will have the form:  FI#, reg0, <offs>
// with no shift amount for the frame offset.
//
static inline unsigned ARM_AM_getAM2Opc(ARM_AM_AddrOpc Opc, unsigned Imm12,
					ARM_AM_ShiftOpc SO, unsigned IdxMode)
{
	CS_ASSERT(Imm12 < (1 << 12) && "Imm too large!");
	bool isSub = Opc == ARM_AM_sub;
	return Imm12 | ((int)isSub << 12) | (SO << 13) | (IdxMode << 16);
}

static inline unsigned ARM_AM_getAM2Offset(unsigned AM2Opc)
{
	return AM2Opc & ((1 << 12) - 1);
}

static inline ARM_AM_AddrOpc ARM_AM_getAM2Op(unsigned AM2Opc)
{
	return ((AM2Opc >> 12) & 1) ? ARM_AM_sub : ARM_AM_add;
}

static inline ARM_AM_ShiftOpc ARM_AM_getAM2ShiftOpc(unsigned AM2Opc)
{
	return (ARM_AM_ShiftOpc)((AM2Opc >> 13) & 7);
}

static inline unsigned ARM_AM_getAM2IdxMode(unsigned AM2Opc)
{
	return (AM2Opc >> 16);
}

//===--------------------------------------------------------------------===//
// Addressing Mode #3
//===--------------------------------------------------------------------===//
//
// This is used for sign-extending loads, and load/store-pair instructions.
//
// addrmode3 := reg +/- reg
// addrmode3 := reg +/- imm8
//
// The first operand is always a Reg.  The second operand is a reg if in
// reg/reg form, otherwise it's reg#0.  The third field encodes the operation
// in bit 8, the immediate in bits 0-7. The fourth operand 9-10 encodes the
// index mode.
/// getAM3Opc - This function encodes the addrmode3 opc field.
static inline unsigned ARM_AM_getAM3Opc(ARM_AM_AddrOpc Opc,
					unsigned char Offset, unsigned IdxMode)
{
	bool isSub = Opc == ARM_AM_sub;
	return ((int)isSub << 8) | Offset | (IdxMode << 9);
}

static inline unsigned char ARM_AM_getAM3Offset(unsigned AM3Opc)
{
	return AM3Opc & 0xFF;
}

static inline ARM_AM_AddrOpc ARM_AM_getAM3Op(unsigned AM3Opc)
{
	return ((AM3Opc >> 8) & 1) ? ARM_AM_sub : ARM_AM_add;
}

static inline unsigned ARM_AM_getAM3IdxMode(unsigned AM3Opc)
{
	return (AM3Opc >> 9);
}

//===--------------------------------------------------------------------===//
// Addressing Mode #4
//===--------------------------------------------------------------------===//
//
// This is used for load / store multiple instructions.
//
// addrmode4 := reg, <mode>
//
// The four modes are:
//    IA - Increment after
//    IB - Increment before
//    DA - Decrement after
//    DB - Decrement before
// For VFP instructions, only the IA and DB modes are valid.
static inline ARM_AM_SubMode ARM_AM_getAM4SubMode(unsigned Mode)
{
	return (ARM_AM_SubMode)(Mode & 0x7);
}

static inline unsigned ARM_AM_getAM4ModeImm(ARM_AM_SubMode SubMode)
{
	return (int)SubMode;
}

//===--------------------------------------------------------------------===//
// Addressing Mode #5
//===--------------------------------------------------------------------===//
//
// This is used for coprocessor instructions, such as FP load/stores.
//
// addrmode5 := reg +/- imm8*4
//
// The first operand is always a Reg.  The second operand encodes the
// operation (add or subtract) in bit 8 and the immediate in bits 0-7.
/// getAM5Opc - This function encodes the addrmode5 opc field.
static inline unsigned ARM_AM_getAM5Opc(ARM_AM_AddrOpc Opc,
					unsigned char Offset)
{
	bool isSub = Opc == ARM_AM_sub;
	return ((int)isSub << 8) | Offset;
}

static inline unsigned char ARM_AM_getAM5Offset(unsigned AM5Opc)
{
	return AM5Opc & 0xFF;
}

static inline ARM_AM_AddrOpc ARM_AM_getAM5Op(unsigned AM5Opc)
{
	return ((AM5Opc >> 8) & 1) ? ARM_AM_sub : ARM_AM_add;
}

//===--------------------------------------------------------------------===//
// Addressing Mode #5 FP16
//===--------------------------------------------------------------------===//
//
// This is used for coprocessor instructions, such as 16-bit FP load/stores.
//
// addrmode5fp16 := reg +/- imm8*2
//
// The first operand is always a Reg.  The second operand encodes the
// operation (add or subtract) in bit 8 and the immediate in bits 0-7.
/// getAM5FP16Opc - This function encodes the addrmode5fp16 opc field.
static inline unsigned ARM_AM_getAM5FP16Opc(ARM_AM_AddrOpc Opc,
					    unsigned char Offset)
{
	bool isSub = Opc == ARM_AM_sub;
	return ((int)isSub << 8) | Offset;
}

static inline unsigned char ARM_AM_getAM5FP16Offset(unsigned AM5Opc)
{
	return AM5Opc & 0xFF;
}

static inline ARM_AM_AddrOpc ARM_AM_getAM5FP16Op(unsigned AM5Opc)
{
	return ((AM5Opc >> 8) & 1) ? ARM_AM_sub : ARM_AM_add;
}

//===--------------------------------------------------------------------===//
// Addressing Mode #6
//===--------------------------------------------------------------------===//
//
// This is used for NEON load / store instructions.
//
// addrmode6 := reg with optional alignment
//
// This is stored in two operands [regaddr, align].  The first is the
// address register.  The second operand is the value of the alignment
// specifier in bytes or zero if no explicit alignment.
// Valid alignments depend on the specific instruction.
//===--------------------------------------------------------------------===//
// NEON/MVE Modified Immediates
//===--------------------------------------------------------------------===//
//
// Several NEON and MVE instructions (e.g., VMOV) take a "modified immediate"
// vector operand, where a small immediate encoded in the instruction
// specifies a full NEON vector value.  These modified immediates are
// represented here as encoded integers.  The low 8 bits hold the immediate
// value; bit 12 holds the "Op" field of the instruction, and bits 11-8 hold
// the "Cmode" field of the instruction.  The interfaces below treat the
// Op and Cmode values as a single 5-bit value.
static inline unsigned ARM_AM_createVMOVModImm(unsigned OpCmode, unsigned Val)
{
	return (OpCmode << 8) | Val;
}

static inline unsigned ARM_AM_getVMOVModImmOpCmode(unsigned ModImm)
{
	return (ModImm >> 8) & 0x1f;
}

static inline unsigned ARM_AM_getVMOVModImmVal(unsigned ModImm)
{
	return ModImm & 0xff;
}

/// decodeVMOVModImm - Decode a NEON/MVE modified immediate value into the
/// element value and the element size in bits.  (If the element size is
/// smaller than the vector, it is splatted into all the elements.)
static inline uint64_t ARM_AM_decodeVMOVModImm(unsigned ModImm,
					       unsigned *EltBits)
{
	unsigned OpCmode = ARM_AM_getVMOVModImmOpCmode(ModImm);
	unsigned Imm8 = ARM_AM_getVMOVModImmVal(ModImm);
	uint64_t Val = 0;

	if (OpCmode == 0xe) {
		// 8-bit vector elements
		Val = Imm8;
		*EltBits = 8;
	} else if ((OpCmode & 0xc) == 0x8) {
		// 16-bit vector elements
		unsigned ByteNum = (OpCmode & 0x6) >> 1;
		Val = Imm8 << (8 * ByteNum);
		*EltBits = 16;
	} else if ((OpCmode & 0x8) == 0) {
		// 32-bit vector elements, zero with one byte set
		unsigned ByteNum = (OpCmode & 0x6) >> 1;
		Val = Imm8 << (8 * ByteNum);
		*EltBits = 32;
	} else if ((OpCmode & 0xe) == 0xc) {
		// 32-bit vector elements, one byte with low bits set
		unsigned ByteNum = 1 + (OpCmode & 0x1);
		Val = (Imm8 << (8 * ByteNum)) | (0xffff >> (8 * (2 - ByteNum)));
		*EltBits = 32;
	} else if (OpCmode == 0x1e) {
		// 64-bit vector elements
		for (unsigned ByteNum = 0; ByteNum < 8; ++ByteNum) {
			if ((ModImm >> ByteNum) & 1)
				Val |= (uint64_t)0xff << (8 * ByteNum);
		}
		*EltBits = 64;
	} else {
		CS_ASSERT_RET_VAL(0 && "Unsupported VMOV immediate", 0);
	}
	return Val;
}

// Generic validation for single-byte immediate (0X00, 00X0, etc).
static inline bool ARM_AM_isNEONBytesplat(unsigned Value, unsigned Size)
{
	CS_ASSERT(Size >= 1 && Size <= 4 && "Invalid size");
	unsigned count = 0;
	for (unsigned i = 0; i < Size; ++i) {
		if (Value & 0xff)
			count++;
		Value >>= 8;
	}
	return count == 1;
}

/// Checks if Value is a correct immediate for instructions like VBIC/VORR.
static inline bool ARM_AM_isNEONi16splat(unsigned Value)
{
	if (Value > 0xffff)
		return false;
	// i16 value with set bits only in one byte X0 or 0X.
	return Value == 0 || ARM_AM_isNEONBytesplat(Value, 2);
}

// Encode NEON 16 bits Splat immediate for instructions like VBIC/VORR
static inline unsigned ARM_AM_encodeNEONi16splat(unsigned Value)
{
	CS_ASSERT(ARM_AM_isNEONi16splat(Value) && "Invalid NEON splat value");
	if (Value >= 0x100)
		Value = (Value >> 8) | 0xa00;
	else
		Value |= 0x800;
	return Value;
}

/// Checks if Value is a correct immediate for instructions like VBIC/VORR.
static inline bool ARM_AM_isNEONi32splat(unsigned Value)
{
	// i32 value with set bits only in one byte X000, 0X00, 00X0, or 000X.
	return Value == 0 || ARM_AM_isNEONBytesplat(Value, 4);
}

/// Encode NEON 32 bits Splat immediate for instructions like VBIC/VORR.
static inline unsigned ARM_AM_encodeNEONi32splat(unsigned Value)
{
	CS_ASSERT(ARM_AM_isNEONi32splat(Value) && "Invalid NEON splat value");
	if (Value >= 0x100 && Value <= 0xff00)
		Value = (Value >> 8) | 0x200;
	else if (Value > 0xffff && Value <= 0xff0000)
		Value = (Value >> 16) | 0x400;
	else if (Value > 0xffffff)
		Value = (Value >> 24) | 0x600;
	return Value;
}

//===--------------------------------------------------------------------===//
// Floating-point Immediates
//
static inline float ARM_AM_getFPImmFloat(unsigned Imm)
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

#endif // CS_ARM_ADDRESSINGMODES_H
