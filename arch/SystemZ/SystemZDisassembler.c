//===------ SystemZDisassembler.cpp - Disassembler for PowerPC ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SYSZ

#include <stdio.h>	// DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "SystemZDisassembler.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../MathExtras.h"

#include "SystemZMCTargetDesc.h"

#define GET_SUBTARGETINFO_ENUM
#include "SystemZGenSubtargetInfo.inc"

#include "CapstoneSystemZModule.h"

static uint64_t getFeatureBits(int mode)
{
	// support everything
	return (uint64_t)-1;
}

bool SystemZ_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *MI,
		uint16_t *size, uint64_t address, void *info)
{
	uint64_t Inst;
	const uint8_t *Table;
	uint16_t I; 

	// The top 2 bits of the first byte specify the size.
	if (*code < 0x40) {
		*size = 2;
		Table = DecoderTable16;
	} else if (*code < 0xc0) {
		*size = 4;
		Table = DecoderTable32;
	} else {
		*size = 6;
		Table = DecoderTable48;
	}

	if (code_len < *size)
		// short of input data
		return false;

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, offsetof(cs_detail, sysz)+sizeof(cs_sysz));
	}

	// Construct the instruction.
	Inst = 0;
	for (I = 0; I < *size; ++I)
		Inst = (Inst << 8) | code[I];

	return decodeInstruction(Table, MI, Inst, address, info, 0);
}

void SystemZ_init(MCRegisterInfo *MRI)
{
	/*
	InitMCRegisterInfo(SystemZRegDesc, 98, RA, PC,
			SystemZMCRegisterClasses, 12,
			SystemZRegUnitRoots,
			49,
			SystemZRegDiffLists,
			SystemZRegStrings,
			SystemZSubRegIdxLists,
			7,
			SystemZSubRegIdxRanges,
			SystemZRegEncodingTable);
	*/

	MCRegisterInfo_InitMCRegisterInfo(MRI, SystemZRegDesc, 194,
			0, 0,
			SystemZMCRegisterClasses, 21,
			0, 0,
			SystemZRegDiffLists,
			0,
			SystemZSubRegIdxLists, 7,
			0);
}

#endif
