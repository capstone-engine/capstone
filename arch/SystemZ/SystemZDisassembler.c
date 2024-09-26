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

//===-- SystemZDisassembler.cpp - Disassembler for SystemZ ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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

#include "SystemZMCTargetDesc.h"
#include "SystemZDisassemblerExtension.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "systemz-disassembler"

static DecodeStatus getInstruction(MCInst *Instr, uint16_t *Size, const uint8_t *Bytes,
			    size_t BytesLen, uint64_t Address,
			    SStream *CStream);

/// tryAddingSymbolicOperand - trys to add a symbolic operand in place of the
/// immediate Value in the MCInst.
///
/// @param Value      - The immediate Value, has had any PC adjustment made by
///                     the caller.
/// @param isBranch   - If the instruction is a branch instruction
/// @param Address    - The starting address of the instruction
/// @param Offset     - The byte offset to this immediate in the instruction
/// @param Width      - The byte width of this immediate in the instruction
///
/// If the getOpInfo() function was set when setupForSymbolicDisassembly() was
/// called then that function is called to get any symbolic information for the
/// immediate in the instruction using the Address, Offset and Width.  If that
/// returns non-zero then the symbolic information it returns is used to create
/// an MCExpr and that is added as an operand to the MCInst.  If getOpInfo()
/// returns zero and isBranch is true then a symbol look up for immediate Value
/// is done and if a symbol is found an MCExpr is created with that, else
/// an MCExpr with the immediate Value is created.  This function returns true
/// if it adds an operand to the MCInst and false otherwise.
static bool tryAddingSymbolicOperand(int64_t Value, bool IsBranch,
				     uint64_t Address, uint64_t Offset,
				     uint64_t Width, MCInst *MI,
				     const void *Decoder)
{
	// return Decoder->tryAddingSymbolicOperand(MI, Value, Address, IsBranch,
	// 					 Offset, Width, /*InstSize=*/0);
	return false;
}

static DecodeStatus decodeRegisterClass(MCInst *Inst, uint64_t RegNo,
					const unsigned *Regs, unsigned Size,
					bool IsAddr)
{
	CS_ASSERT((RegNo < Size && "Invalid register"));
	if (IsAddr && RegNo == 0) {
		RegNo = SystemZ_NoRegister;
	} else {
		RegNo = Regs[RegNo];
		if (RegNo == 0)
			return MCDisassembler_Fail;
	}
	MCOperand_CreateReg0(Inst, (RegNo));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GR32Regs, 16, false);
}

static DecodeStatus DecodeGRH32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						uint64_t Address,
						const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GRH32Regs, 16, false);
}

static DecodeStatus DecodeGR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GR64Regs, 16, false);
}

static DecodeStatus DecodeGR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						uint64_t Address,
						const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GR128Regs, 16, false);
}

static DecodeStatus DecodeADDR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GR32Regs, 16, true);
}

static DecodeStatus DecodeADDR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_GR64Regs, 16, true);
}

static DecodeStatus DecodeFP32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_FP32Regs, 16, false);
}

static DecodeStatus DecodeFP64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_FP64Regs, 16, false);
}

static DecodeStatus DecodeFP128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						uint64_t Address,
						const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_FP128Regs, 16, false);
}

static DecodeStatus DecodeVR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_VR32Regs, 32, false);
}

static DecodeStatus DecodeVR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_VR64Regs, 32, false);
}

static DecodeStatus DecodeVR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
						uint64_t Address,
						const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_VR128Regs, 32, false);
}

static DecodeStatus DecodeAR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_AR32Regs, 16, false);
}

static DecodeStatus DecodeCR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	return decodeRegisterClass(Inst, RegNo, SystemZMC_CR64Regs, 16, false);
}

#define DEFINE_decodeUImmOperand(N) \
	static DecodeStatus CONCAT(decodeUImmOperand, N)(MCInst * Inst, \
							 uint64_t Imm) \
	{ \
		if (!isUIntN(N, Imm)) \
			return MCDisassembler_Fail; \
		MCOperand_CreateImm0(Inst, (Imm)); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeUImmOperand(1);
DEFINE_decodeUImmOperand(2);
DEFINE_decodeUImmOperand(3);
DEFINE_decodeUImmOperand(4);
DEFINE_decodeUImmOperand(8);
DEFINE_decodeUImmOperand(12);
DEFINE_decodeUImmOperand(16);
DEFINE_decodeUImmOperand(32);

#define DEFINE_decodeSImmOperand(N) \
	static DecodeStatus CONCAT(decodeSImmOperand, N)(MCInst * Inst, \
							 uint64_t Imm) \
	{ \
		if (!isUIntN(N, Imm)) \
			return MCDisassembler_Fail; \
		MCOperand_CreateImm0(Inst, (SignExtend64((Imm), N))); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeSImmOperand(8);
DEFINE_decodeSImmOperand(16);
DEFINE_decodeSImmOperand(20);
DEFINE_decodeSImmOperand(32);

static DecodeStatus decodeU1ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 1)(Inst, Imm);
}

static DecodeStatus decodeU2ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 2)(Inst, Imm);
}

static DecodeStatus decodeU3ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 3)(Inst, Imm);
}

static DecodeStatus decodeU4ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 4)(Inst, Imm);
}

static DecodeStatus decodeU8ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 8)(Inst, Imm);
}

static DecodeStatus decodeU12ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 12)(Inst, Imm);
}

static DecodeStatus decodeU16ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 16)(Inst, Imm);
}

static DecodeStatus decodeU32ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeUImmOperand, 32)(Inst, Imm);
}

static DecodeStatus decodeS8ImmOperand(MCInst *Inst, uint64_t Imm,
				       uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeSImmOperand, 8)(Inst, Imm);
}

static DecodeStatus decodeS16ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeSImmOperand, 16)(Inst, Imm);
}

static DecodeStatus decodeS20ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeSImmOperand, 20)(Inst, Imm);
}

static DecodeStatus decodeS32ImmOperand(MCInst *Inst, uint64_t Imm,
					uint64_t Address, const void *Decoder)
{
	return CONCAT(decodeSImmOperand, 32)(Inst, Imm);
}

#define DEFINE_decodeLenOperand(N) \
	static DecodeStatus CONCAT(decodeLenOperand, \
				   N)(MCInst * Inst, uint64_t Imm, \
				      uint64_t Address, const void *Decoder) \
	{ \
		if (!isUIntN(N, Imm)) \
			return MCDisassembler_Fail; \
		MCOperand_CreateImm0(Inst, (Imm + 1)); \
		return MCDisassembler_Success; \
	}
DEFINE_decodeLenOperand(8);
DEFINE_decodeLenOperand(4);

#define DEFINE_decodePCDBLOperand(N) \
	static DecodeStatus CONCAT(decodePCDBLOperand, N)( \
		MCInst * Inst, uint64_t Imm, uint64_t Address, bool isBranch, \
		const void *Decoder) \
	{ \
		CS_ASSERT((isUIntN(N, Imm) && "Invalid PC-relative offset")); \
		uint64_t Value = SignExtend64((Imm), N) * 2 + Address; \
\
		if (!tryAddingSymbolicOperand(Value, isBranch, Address, 2, \
					      N / 8, Inst, Decoder)) \
			MCOperand_CreateImm0(Inst, (Value)); \
\
		return MCDisassembler_Success; \
	}
DEFINE_decodePCDBLOperand(12);
DEFINE_decodePCDBLOperand(16);
DEFINE_decodePCDBLOperand(24);
DEFINE_decodePCDBLOperand(32);

static DecodeStatus decodePC12DBLBranchOperand(MCInst *Inst, uint64_t Imm,
					       uint64_t Address,
					       const void *Decoder)
{
	return CONCAT(decodePCDBLOperand, 12)(Inst, Imm, Address, true,
					      Decoder);
}

static DecodeStatus decodePC16DBLBranchOperand(MCInst *Inst, uint64_t Imm,
					       uint64_t Address,
					       const void *Decoder)
{
	return CONCAT(decodePCDBLOperand, 16)(Inst, Imm, Address, true,
					      Decoder);
}

static DecodeStatus decodePC24DBLBranchOperand(MCInst *Inst, uint64_t Imm,
					       uint64_t Address,
					       const void *Decoder)
{
	return CONCAT(decodePCDBLOperand, 24)(Inst, Imm, Address, true,
					      Decoder);
}

static DecodeStatus decodePC32DBLBranchOperand(MCInst *Inst, uint64_t Imm,
					       uint64_t Address,
					       const void *Decoder)
{
	return CONCAT(decodePCDBLOperand, 32)(Inst, Imm, Address, true,
					      Decoder);
}

static DecodeStatus decodePC32DBLOperand(MCInst *Inst, uint64_t Imm,
					 uint64_t Address, const void *Decoder)
{
	return CONCAT(decodePCDBLOperand, 32)(Inst, Imm, Address, false,
					      Decoder);
}

#include "SystemZGenDisassemblerTables.inc"

static DecodeStatus getInstruction(MCInst *MI, uint16_t *Size, const uint8_t *Bytes,
			    size_t BytesLen, uint64_t Address, SStream *CS)
{
	// Get the first two bytes of the instruction.
	*Size = 0;
	if (BytesLen < 2)
		return MCDisassembler_Fail;

	// The top 2 bits of the first byte specify the size.
	const uint8_t *Table;
	uint64_t Inst = 0;
	if (Bytes[0] < 0x40) {
		*Size = 2;
		Table = DecoderTable16;
		Inst = readBytes16(MI, Bytes);
	} else if (Bytes[0] < 0xc0) {
		if (BytesLen < 4) {
			return MCDisassembler_Fail;
		}
		*Size = 4;
		Table = DecoderTable32;
		Inst = readBytes32(MI, Bytes);
	} else {
		if (BytesLen < 6) {
			return MCDisassembler_Fail;
		}
		*Size = 6;
		Table = DecoderTable48;
		Inst = readBytes48(MI, Bytes);
	}

	// Read any remaining bytes.
	if (BytesLen < *Size) {
		*Size = BytesLen;
		return MCDisassembler_Fail;
	}

	return decodeInstruction_8(Table, MI, Inst, Address, NULL);
}

DecodeStatus SystemZ_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				     size_t BytesLen, MCInst *MI,
				     uint16_t *Size, uint64_t Address,
				     void *Info)
{
	return getInstruction(MI, Size, Bytes, BytesLen, MI->address, NULL);
}
