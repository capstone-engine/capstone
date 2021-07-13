//===------ SparcDisassembler.cpp - Disassembler for PowerPC ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SPARC

#include <stdio.h>	// DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "SparcDisassembler.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../MathExtras.h"

#include "CapstoneSparcModule.h"

static uint64_t getFeatureBits(int mode)
{
	// support everything
	return (uint64_t)-1;
}

//#define GET_SUBTARGETINFO_ENUM
//#include "SparcGenSubtargetInfo.inc"

/// readInstruction - read four bytes and return 32 bit word.
static DecodeStatus readInstruction32(const uint8_t *code, size_t len, uint32_t *Insn)
{
	if (len < 4)
		// not enough data
		return MCDisassembler_Fail;

	// Encoded as a big-endian 32-bit word in the stream.
	*Insn = (code[3] <<  0) |
		(code[2] <<  8) |
		(code[1] << 16) |
		((uint32_t) code[0] << 24);

	return MCDisassembler_Success;
}

bool Sparc_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *MI,
		uint16_t *size, uint64_t address, void *info)
{
	uint32_t Insn;
	DecodeStatus Result;
	
	Result = readInstruction32(code, code_len, &Insn);
	if (Result == MCDisassembler_Fail)
		return false;

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, sparc)+sizeof(cs_sparc));
	}

	Result = decodeInstruction_4(DecoderTableSparc32, MI, Insn, address,
			(MCRegisterInfo *)info, 0);
	if (Result != MCDisassembler_Fail) {
		*size = 4;
		return true;
	}

	return false;
}

void Sparc_init(MCRegisterInfo *MRI)
{
	/*
	InitMCRegisterInfo(SparcRegDesc, 119, RA, PC,
			SparcMCRegisterClasses, 8,
			SparcRegUnitRoots,
			86,
			SparcRegDiffLists,
			SparcRegStrings,
			SparcSubRegIdxLists,
			7,
			SparcSubRegIdxRanges,
			SparcRegEncodingTable);
	*/

	MCRegisterInfo_InitMCRegisterInfo(MRI, SparcRegDesc, 119,
			0, 0,
			SparcMCRegisterClasses, 8,
			0, 0,
			SparcRegDiffLists,
			0,
			SparcSubRegIdxLists, 7,
			0);
}

#endif
