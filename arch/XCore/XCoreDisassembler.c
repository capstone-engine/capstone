//===------ XCoreDisassembler.cpp - Disassembler for PowerPC ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_XCORE

#include <stdio.h>	// DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "XCoreDisassembler.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../MathExtras.h"

static uint64_t getFeatureBits(int mode)
{
	// support everything
	return (uint64_t)-1;
}

#include "CapstoneXCoreModule.h"

static bool readInstruction16(const uint8_t *code, size_t code_len, uint16_t *insn)
{
	if (code_len < 2)
		// insufficient data
		return false;

	// Encoded as a little-endian 16-bit word in the stream.
	*insn = (code[0] <<  0) | (code[1] <<  8);
	return true;
}

static bool readInstruction32(const uint8_t *code, size_t code_len, uint32_t *insn)
{
	if (code_len < 4)
		// insufficient data
		return false;

	// Encoded as a little-endian 32-bit word in the stream.
	*insn = (code[0] << 0) | (code[1] << 8) | (code[2] << 16) | ((uint32_t) code[3] << 24);

	return true;
}

bool XCore_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *MI,
		uint16_t *size, uint64_t address, void *info)
{
	uint16_t insn16;
	uint32_t insn32;
	DecodeStatus Result;

	if (!readInstruction16(code, code_len, &insn16)) {
		return false;
	}

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, xcore)+sizeof(cs_xcore));
	}

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_2(DecoderTable16, MI, insn16, address, info, 0);
	if (Result != MCDisassembler_Fail) {
		*size = 2;
		return true;
	}

	if (!readInstruction32(code, code_len, &insn32)) {
		return false;
	}

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_4(DecoderTable32, MI, insn32, address, info, 0);
	if (Result != MCDisassembler_Fail) {
		*size = 4;
		return true;
	}

	return false;
}

void XCore_init(MCRegisterInfo *MRI)
{
	/*
	InitMCRegisterInfo(XCoreRegDesc, 17, RA, PC,
			XCoreMCRegisterClasses, 2,
			XCoreRegUnitRoots,
			16,
			XCoreRegDiffLists,
			XCoreRegStrings,
			XCoreSubRegIdxLists,
			1,
			XCoreSubRegIdxRanges,
			XCoreRegEncodingTable);
	*/


	MCRegisterInfo_InitMCRegisterInfo(MRI, XCoreRegDesc, 17,
			0, 0,
			XCoreMCRegisterClasses, 2,
			0, 0,
			XCoreRegDiffLists,
			0,
			XCoreSubRegIdxLists, 1,
			0);
}

#endif
