//===-- AArch64BaseInfo.cpp - AArch64 Base encoding information------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides basic encoding and assembly information for AArch64.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_ARM64

#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#pragma warning(disable:4996)			// disable MSVC's warning on strcpy()
#pragma warning(disable:28719)		// disable MSVC's warning on strcpy()
#endif

#include "../../utils.h"

#include <stdio.h>
#include <stdlib.h>

#include "AArch64BaseInfo.h"
#include "AArch64GenSystemOperands.inc"

const char *A64NamedImmMapper_toString(const A64NamedImmMapper *N, uint32_t Value, bool *Valid)
{
	unsigned i;
	for (i = 0; i < N->NumPairs; ++i) {
		if (N->Pairs[i].Value == Value) {
			*Valid = true;
			return N->Pairs[i].Name;
		}
	}

	*Valid = false;
	return 0;
}

// compare s1 with lower(s2)
// return true if s1 == lower(f2), and false otherwise
static bool compare_lower_str(const char *s1, const char *s2)
{
	bool res;
	char *lower = cs_strdup(s2), *c;
	for (c = lower; *c; c++)
		*c = (char)tolower((int) *c);

	res = (strcmp(s1, lower) == 0);
	cs_mem_free(lower);

	return res;
}

uint32_t A64NamedImmMapper_fromString(const A64NamedImmMapper *N, char *Name, bool *Valid)
{
	unsigned i;
	for (i = 0; i < N->NumPairs; ++i) {
		if (compare_lower_str(N->Pairs[i].Name, Name)) {
			*Valid = true;
			return N->Pairs[i].Value;
		}
	}

	*Valid = false;
	return (uint32_t)-1;
}

bool A64NamedImmMapper_validImm(const A64NamedImmMapper *N, uint32_t Value)
{
	return Value < N->TooBigImm;
}

// return a string representing the number X
// NOTE: caller must free() the result itself to avoid memory leak
static char *utostr(uint64_t X, bool isNeg)
{
	char Buffer[22];
	char *BufPtr = Buffer+21;
	char *result;

	Buffer[21] = '\0';
	if (X == 0) *--BufPtr = '0';  // Handle special case...

	while (X) {
		*--BufPtr = X % 10 + '0';
		X /= 10;
	}

	if (isNeg) *--BufPtr = '-';   // Add negative sign...

	result = cs_strdup(BufPtr);
	return result;
}

// result must be a big enough buffer: 128 bytes is more than enough
void A64SysRegMapper_toString(const A64SysRegMapper *S, uint32_t Bits, char *result)
{
	int dummy;
	uint32_t Op0, Op1, CRn, CRm, Op2;
	char *Op0S, *Op1S, *CRnS, *CRmS, *Op2S;
	unsigned i;

	// First search the registers shared by all
	for (i = 0; i < ARR_SIZE(SysRegPairs); ++i) {
		if (SysRegPairs[i].Value == Bits) {
			strcpy(result, SysRegPairs[i].Name);
			return;
		}
	}

	// Next search for target specific registers
	// if (FeatureBits & AArch64_ProcCyclone) {
	if (true) {
		for (i = 0; i < ARR_SIZE(CycloneSysRegPairs); ++i) {
			if (CycloneSysRegPairs[i].Value == Bits) {
				strcpy(result, CycloneSysRegPairs[i].Name);
				return;
			}
		}
	}

	// Now try the instruction-specific registers (either read-only or
	// write-only).
	for (i = 0; i < S->NumInstPairs; ++i) {
		if (S->InstPairs[i].Value == Bits) {
			strcpy(result, S->InstPairs[i].Name);
			return;
		}
	}

	Op0 = (Bits >> 14) & 0x3;
	Op1 = (Bits >> 11) & 0x7;
	CRn = (Bits >> 7) & 0xf;
	CRm = (Bits >> 3) & 0xf;
	Op2 = Bits & 0x7;

	Op0S = utostr(Op0, false);
	Op1S = utostr(Op1, false);
	CRnS = utostr(CRn, false);
	CRmS = utostr(CRm, false);
	Op2S = utostr(Op2, false);

	//printf("Op1S: %s, CRnS: %s, CRmS: %s, Op2S: %s\n", Op1S, CRnS, CRmS, Op2S);
	dummy = cs_snprintf(result, 128, "s3_%s_c%s_c%s_%s", Op1S, CRnS, CRmS, Op2S);
	(void)dummy;

	cs_mem_free(Op0S);
	cs_mem_free(Op1S);
	cs_mem_free(CRnS);
	cs_mem_free(CRmS);
	cs_mem_free(Op2S);
}

const A64NamedImmMapper A64TLBI_TLBIMapper = {
	TLBIPairs,
	ARR_SIZE(TLBIPairs),
	0,
};

const A64NamedImmMapper A64AT_ATMapper = {
	ATPairs,
	ARR_SIZE(ATPairs),
	0,
};

const A64NamedImmMapper A64DB_DBarrierMapper = {
	DBarrierPairs,
	ARR_SIZE(DBarrierPairs),
	16,
};

const A64NamedImmMapper A64DC_DCMapper = {
	DCPairs,
	ARR_SIZE(DCPairs),
	0,
};

const A64NamedImmMapper A64IC_ICMapper = {
	ICPairs,
	ARR_SIZE(ICPairs),
	0,
};

const A64NamedImmMapper A64ISB_ISBMapper = {
	ISBPairs,
	ARR_SIZE(ISBPairs),
	16,
};

const A64NamedImmMapper A64PRFM_PRFMMapper = {
	PRFMPairs,
	ARR_SIZE(PRFMPairs),
	32,
};

const A64NamedImmMapper A64PState_PStateMapper = {
	PStatePairs,
	ARR_SIZE(PStatePairs),
	0,
};

const A64SysRegMapper AArch64_MRSMapper = {
	NULL,
	MRSPairs,
	ARR_SIZE(MRSPairs),
};

const A64SysRegMapper AArch64_MSRMapper = {
	NULL,
	MSRPairs,
	ARR_SIZE(MSRPairs),
};

#endif
