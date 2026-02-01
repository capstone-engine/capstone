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

//===-- RISCVBaseInfo.cpp - Top level definitions for RISC-V MC -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone enum definitions for the RISC-V target
// useful for the compiler back-end and the MC libraries.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "RISCVBaseInfo.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

typedef struct {
	unsigned value;
	bool isFractional;
} VLMULDecodeResult;
VLMULDecodeResult decodeVLMUL(RISCVII_VLMUL VLMUL)
{
	switch (VLMUL) {
	default:
		CS_ASSERT(0 && "Unexpected LMUL value!");
	case RISCVII_LMUL_1:
	case RISCVII_LMUL_2:
	case RISCVII_LMUL_4:
	case RISCVII_LMUL_8: {
		VLMULDecodeResult result = { .value = 1 << (unsigned)(VLMUL),
					     .isFractional = false };
		return result;
	}
	case RISCVII_LMUL_F2:
	case RISCVII_LMUL_F4:
	case RISCVII_LMUL_F8: {
		VLMULDecodeResult result = { .value = 1 << (8 -
							    (unsigned)(VLMUL)),
					     .isFractional = true };
		return result;
	}
	}
}

void printVType(unsigned VType, SStream *OS)
{
	unsigned Sew = RISCVVType_getSEW(VType);
	SStream_concat(OS, "%s", "e");
	printUInt64(OS, Sew);

	unsigned LMul;
	bool Fractional;
	VLMULDecodeResult result = decodeVLMUL(RISCVVType_getVLMUL(VType));
	LMul = result.value;
	Fractional = result.isFractional;

	if (Fractional)
		SStream_concat0(OS, ", mf");
	else
		SStream_concat0(OS, ", m");
	printUInt64(OS, LMul);

	if (RISCVVType_isTailAgnostic(VType))
		SStream_concat0(OS, ", ta");
	else
		SStream_concat0(OS, ", tu");

	if (RISCVVType_isMaskAgnostic(VType))
		SStream_concat0(OS, ", ma");
	else
		SStream_concat0(OS, ", mu");
}

typedef struct {
	uint8_t first;
	uint8_t second;
} LoadFP32ImmArrElement;

// Lookup table for fli.s for entries 2-31.
static const LoadFP32ImmArrElement LoadFP32ImmArr[] = {
	{ 0x6f, 0x00 }, { 0x70, 0x00 }, { 0x77, 0x00 }, { 0x78, 0x00 },
	{ 0x7b, 0x00 }, { 0x7c, 0x00 }, { 0x7d, 0x00 }, { 0x7d, 0x01 },
	{ 0x7d, 0x02 }, { 0x7d, 0x03 }, { 0x7e, 0x00 }, { 0x7e, 0x01 },
	{ 0x7e, 0x02 }, { 0x7e, 0x03 }, { 0x7f, 0x00 }, { 0x7f, 0x01 },
	{ 0x7f, 0x02 }, { 0x7f, 0x03 }, { 0x80, 0x00 }, { 0x80, 0x01 },
	{ 0x80, 0x02 }, { 0x81, 0x00 }, { 0x82, 0x00 }, { 0x83, 0x00 },
	{ 0x86, 0x00 }, { 0x87, 0x00 }, { 0x8e, 0x00 }, { 0x8f, 0x00 },
	{ 0xff, 0x00 }, { 0xff, 0x02 },
};

float getFPImm(unsigned Imm)
{
	CS_ASSERT(Imm != 1 && Imm != 30 && Imm != 31 &&
		  "Unsupported immediate");
	CS_ASSERT((Imm == 0 || (Imm >= 2 && Imm < 30)) &&
		  "Unsupported immediate");
	// Entry 0 is -1.0, the only negative value. Entry 16 is 1.0.
	uint32_t Sign = 0;
	if (Imm == 0) {
		Sign = 0x01;
		Imm = 16;
	}

	uint32_t Exp = LoadFP32ImmArr[Imm - 2].first;
	uint32_t Mantissa = LoadFP32ImmArr[Imm - 2].second;

	uint32_t I = Sign << 31 | Exp << 23 | Mantissa << 21;
	float result;
	memcpy(&result, &I, sizeof(float));
	return result;
}

void RISCVZC_printSpimm(int64_t Spimm, SStream *OS)
{
	printInt32(OS, Spimm);
}

// namespace llvm
