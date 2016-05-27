/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "TriCoreMapping.h"

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

static name_map reg_name_maps[] = {
	{ TRICORE_REG_INVALID, NULL },

	{ TRICORE_REG_D0, "d0" },
	{ TRICORE_REG_D1, "d1" },
	{ TRICORE_REG_D2, "d2" },
	{ TRICORE_REG_D3, "d3" },
	{ TRICORE_REG_D4, "d4" },
	{ TRICORE_REG_D5, "d5" },
	{ TRICORE_REG_D6, "d6" },
	{ TRICORE_REG_D7, "d7" },
	{ TRICORE_REG_D8, "d8" },
	{ TRICORE_REG_D9, "d9" },
	{ TRICORE_REG_D10, "d10" },
	{ TRICORE_REG_D11, "d11" },
	{ TRICORE_REG_D12, "d12" },
	{ TRICORE_REG_D13, "d13" },
	{ TRICORE_REG_D14, "d14" },
	{ TRICORE_REG_D15, "d15" },
	{ TRICORE_REG_A0, "a0" },
	{ TRICORE_REG_A1, "a1" },
	{ TRICORE_REG_A2, "a2" },
	{ TRICORE_REG_A3, "a3" },
	{ TRICORE_REG_A4, "a4" },
	{ TRICORE_REG_A5, "a5" },
	{ TRICORE_REG_A6, "a6" },
	{ TRICORE_REG_A7, "a7" },
	{ TRICORE_REG_A8, "a8" },
	{ TRICORE_REG_A9, "a9" },
	{ TRICORE_REG_A10, "a10" },
	{ TRICORE_REG_A11, "a11" },
	{ TRICORE_REG_A12, "a12" },
	{ TRICORE_REG_A13, "a13" },
	{ TRICORE_REG_A14, "a14" },
	{ TRICORE_REG_A15, "a15" },
	{ TRICORE_REG_E0, "e0" },
	{ TRICORE_REG_E2, "e2" },
	{ TRICORE_REG_E4, "e4" },
	{ TRICORE_REG_E6, "e6" },
	{ TRICORE_REG_E8, "e8" },
	{ TRICORE_REG_E10, "e10" },
	{ TRICORE_REG_E12, "e12" },
	{ TRICORE_REG_E14, "e14" },

	// control registers
	{ TRICORE_REG_PSW, "psw" },
	{ TRICORE_REG_PCXI, "pcxi" },
	{ TRICORE_REG_PC, "pc" },
	{ TRICORE_REG_FCX, "fcx" },
};

const char *TriCore_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= TRICORE_REG_ENDING)
		return NULL;

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

tricore_reg TriCore_reg_id(char *name)
{
	int i;

	for(i = 1; i < ARR_SIZE(reg_name_maps); i++) {
		if (!strcmp(name, reg_name_maps[i].name))
			return reg_name_maps[i].id;
	}

	// not found
	return 0;
}

static insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
		TriCore_ABS, TRICORE_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDArr, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDCrc, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDCrr, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDIrlc, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDXrc, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDXrr, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDi64, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDi64C, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDrc, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDrr, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDsrc, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDsrr, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDNrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDNrc64, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_EQrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_EQrr, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GEUrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GE_Urr, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GErc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LTUrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LT_Urr, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LTrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDrc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDrc64, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDrr, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDsc, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDsrr, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDsrr64, TRICORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_CALLb, TRICORE_INS_CALL,
#ifndef CAPSTONE_DIET
		{ TriCore_A10, 0 }, { TriCore_A11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_DEXTRrrpw, TRICORE_INS_DEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_EQrc, TRICORE_INS_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_EQrr, TRICORE_INS_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_EXTRrrpw, TRICORE_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_GErc, TRICORE_INS_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_GErr, TRICORE_INS_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_IMASKrcpw, TRICORE_INS_IMASK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_JNZsbr, TRICORE_INS_JNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_JZsbr, TRICORE_INS_JZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_Jb, TRICORE_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDBUbo, TRICORE_INS_LDBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDBbo, TRICORE_INS_LDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDDbo, TRICORE_INS_LDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDHUbo, TRICORE_INS_LDHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDHbo, TRICORE_INS_LDH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LDWbo, TRICORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LTrc, TRICORE_INS_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LTrr, TRICORE_INS_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVAArr, TRICORE_INS_MOVAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVAAsrr, TRICORE_INS_MOVAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVArr, TRICORE_INS_MOVA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVDrr, TRICORE_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVHrlc, TRICORE_INS_MOVH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVUrlc, TRICORE_INS_MOVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVi32, TRICORE_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVrlc, TRICORE_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVrr, TRICORE_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOVsrc, TRICORE_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MULrc, TRICORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MULrr2, TRICORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MULsrr, TRICORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NANDrc, TRICORE_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NANDrr, TRICORE_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NErc, TRICORE_INS_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NErr, TRICORE_INS_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NORrc, TRICORE_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NORrr, TRICORE_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NOTrr64, TRICORE_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_NOTsr, TRICORE_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORNrc, TRICORE_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORNrc64, TRICORE_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_GEUrc, TRICORE_INS_OR_GEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	
	},
	{
		TriCore_OR_GErc, TRICORE_INS_OR_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_GErr, TRICORE_INS_OR_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_LTUrc, TRICORE_INS_OR_LTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_LTrc, TRICORE_INS_OR_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_LTrr, TRICORE_INS_OR_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_NErc, TRICORE_INS_OR_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_NErr, TRICORE_INS_OR_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORrc, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORrc64, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORrr, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORsc, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORsrr, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ORsrr64, TRICORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_RET, TRICORE_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_RSUBrc, TRICORE_INS_RSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_RSUBsr, TRICORE_INS_RSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SHArc, TRICORE_INS_SHA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SHArr, TRICORE_INS_SHA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SHrc, TRICORE_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SHrr, TRICORE_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_STAbo, TRICORE_INS_STA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_STBbo, TRICORE_INS_STB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_STDbo, TRICORE_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_STHbo, TRICORE_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_STWbo, TRICORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBArr, TRICORE_INS_SUBA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBAsc, TRICORE_INS_SUBA,
#ifndef CAPSTONE_DIET
		{ TriCore_A10, 0 }, { TriCore_A10, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBCrr, TRICORE_INS_SUBC,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBXrr, TRICORE_INS_SUBX,
#ifndef CAPSTONE_DIET
		{ TriCore_PSW, 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBi64, TRICORE_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { TriCore_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_Select8, TRICORE_INS_Select8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XNORrc, TRICORE_INS_XNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORrc, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORrc64, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORrcneg64, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORrr, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORsrr, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XORsrr64, TRICORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
};

// given internal insn id, return public instruction info
void TriCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned short i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = TRICORE_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static name_map insn_name_maps[] = {
	{ TRICORE_INS_INVALID, NULL },

	{ TRICORE_INS_ABS, "abs" },
	{ TRICORE_INS_ADD, "add" },
	{ TRICORE_INS_AND, "and" },
	{ TRICORE_INS_CALL, "call" },
	{ TRICORE_INS_DEXTR, "dextr" },
	{ TRICORE_INS_EQ, "eq" },
	{ TRICORE_INS_EXTR, "extr" },
	{ TRICORE_INS_GE, "ge" },
	{ TRICORE_INS_IMASK, "imask" },
	{ TRICORE_INS_JNZ, "jnz" },
	{ TRICORE_INS_JZ, "jz" },
	{ TRICORE_INS_J, "j" },
	{ TRICORE_INS_LDBU, "ldbu" },
	{ TRICORE_INS_LDB, "ldb" },
	{ TRICORE_INS_LDD, "ldd" },
	{ TRICORE_INS_LDHU, "ldhu" },
	{ TRICORE_INS_LDH, "ldh" },
	{ TRICORE_INS_LDW, "ldw" },
	{ TRICORE_INS_LT, "lt" },
	{ TRICORE_INS_MOVAA, "movaa" },
	{ TRICORE_INS_MOVA, "mova" },
	{ TRICORE_INS_MOVD, "movd" },
	{ TRICORE_INS_MOVH, "movh" },
	{ TRICORE_INS_MOVU, "movu" },
	{ TRICORE_INS_MOV, "mov" },
	{ TRICORE_INS_MUL, "mul" },
	{ TRICORE_INS_NAND, "nand" },
	{ TRICORE_INS_NE, "ne" },
	{ TRICORE_INS_NOR, "nor" },
	{ TRICORE_INS_NOT, "not" },
	{ TRICORE_INS_ORN, "orn" },
	{ TRICORE_INS_OR_GEU, "or.geu" },
	{ TRICORE_INS_OR_GE, "or.ge" },
	{ TRICORE_INS_OR_LTU, "or.ltu" },
	{ TRICORE_INS_OR_LT, "or.lt" },
	{ TRICORE_INS_OR_NE, "or.ne" },
	{ TRICORE_INS_OR, "or" },
	{ TRICORE_INS_RET, "ret" },
	{ TRICORE_INS_RSUB, "rsub" },
	{ TRICORE_INS_SHA, "sha" },
	{ TRICORE_INS_SH, "sh" },
	{ TRICORE_INS_STA, "sta" },
	{ TRICORE_INS_STB, "stb" },
	{ TRICORE_INS_STD, "std" },
	{ TRICORE_INS_STH, "sth" },
	{ TRICORE_INS_STW, "stw" },
	{ TRICORE_INS_SUBA, "suba" },
	{ TRICORE_INS_SUBC, "subc" },
	{ TRICORE_INS_SUBX, "subx" },
	{ TRICORE_INS_SUB, "sub" },
	{ TRICORE_INS_Select8, "select8" },
	{ TRICORE_INS_XNOR, "xnor" },
	{ TRICORE_INS_XOR, "xor" },
};

// special alias insn
static name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *TriCore_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= TRICORE_INS_ENDING)
		return NULL;

	// handle special alias first
	for (i = 0; i < ARR_SIZE(alias_insn_names); i++) {
		if (alias_insn_names[i].id == id)
			return alias_insn_names[i].name;
	}

	return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

// map internal raw register to 'public' register
tricore_reg TriCore_map_register(unsigned int r)
{
	static unsigned int map[] = { 0,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif
