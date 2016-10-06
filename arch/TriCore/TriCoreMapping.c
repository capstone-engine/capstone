/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "TriCoreMapping.h"

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
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
#endif

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
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDCrc, TRICORE_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDCrr, TRICORE_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDIrlc, TRICORE_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDXrc, TRICORE_INS_ADDX,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDXrr, TRICORE_INS_ADDX,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADD_Arr, TRICORE_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDi64, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ADDi64C, TRICORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
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
		TriCore_ANDNrc, TRICORE_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ANDNrc64, TRICORE_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_EQrc, TRICORE_INS_AND_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_EQrr, TRICORE_INS_AND_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GE_Urc, TRICORE_INS_AND_GE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GE_Urr, TRICORE_INS_AND_GE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GErc, TRICORE_INS_AND_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_GErr, TRICORE_INS_AND_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LT_Urc, TRICORE_INS_AND_LT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LT_Urr, TRICORE_INS_AND_LT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LTrc, TRICORE_INS_AND_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_LTrr, TRICORE_INS_AND_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_NErc, TRICORE_INS_AND_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_AND_NErr, TRICORE_INS_AND_NE,
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
		{ TRICORE_REG_A10, 0 }, { TRICORE_REG_A11, 0 }, { 0 }, 0, 0
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
		TriCore_JNZsb, TRICORE_INS_JNZ,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PC, TRICORE_REG_D15, 0 }, { TRICORE_REG_PC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_JNZsbr, TRICORE_INS_JNZ,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PC, 0 }, { TRICORE_REG_PC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_JZsb, TRICORE_INS_JZ,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PC, TRICORE_REG_D15, 0 }, { TRICORE_REG_PC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_JZsbr, TRICORE_INS_JZ,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PC, 0 }, { TRICORE_REG_PC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_Jb, TRICORE_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_BUbo, TRICORE_INS_LD_BU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_Bbo, TRICORE_INS_LD_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_Dbo, TRICORE_INS_LD_D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_HUbo, TRICORE_INS_LD_HU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_Hbo, TRICORE_INS_LD_H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_LD_Wbo, TRICORE_INS_LD_W,
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
		TriCore_MOVHrlc, TRICORE_INS_MOVH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOV_AArr, TRICORE_INS_MOV_AA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOV_AAsrr, TRICORE_INS_MOV_AA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOV_Arr, TRICORE_INS_MOV_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOV_Drr, TRICORE_INS_MOV_D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MOV_Urlc, TRICORE_INS_MOV_U,
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
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MULrr2, TRICORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_MULsrr, TRICORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
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
		TriCore_OR_EQrc, TRICORE_INS_OR_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_EQrr, TRICORE_INS_OR_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_GE_Urc, TRICORE_INS_OR_GE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	
	},
	{
		TriCore_OR_GE_Urr, TRICORE_INS_OR_GE_U,
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
		TriCore_OR_LT_Urc, TRICORE_INS_OR_LT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_OR_LT_Urr, TRICORE_INS_OR_LT_U,
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
		TriCore_ST_Abo, TRICORE_INS_ST_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ST_Bbo, TRICORE_INS_ST_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ST_Dbo, TRICORE_INS_ST_D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ST_Hbo, TRICORE_INS_ST_H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_ST_Wbo, TRICORE_INS_ST_W,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBCrr, TRICORE_INS_SUBC,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBXrr, TRICORE_INS_SUBX,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_PSW, 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUB_Arr, TRICORE_INS_SUB_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUB_Asc, TRICORE_INS_SUB_A,
#ifndef CAPSTONE_DIET
		{ TRICORE_REG_A10, 0 }, { TRICORE_REG_A10, 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_SUBi64, TRICORE_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { TRICORE_REG_PSW, 0 }, { 0 }, 0, 0
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
		TriCore_XOR_EQrc, TRICORE_INS_XOR_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_EQrr, TRICORE_INS_XOR_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_GE_Urc, TRICORE_INS_XOR_GE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_GE_Urr, TRICORE_INS_XOR_GE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_GErc, TRICORE_INS_XOR_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_GErr, TRICORE_INS_XOR_GE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_LT_Urc, TRICORE_INS_XOR_LT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_LT_Urr, TRICORE_INS_XOR_LT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_LTrc, TRICORE_INS_XOR_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_LTrr, TRICORE_INS_XOR_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_NErc, TRICORE_INS_XOR_NE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		TriCore_XOR_NErr, TRICORE_INS_XOR_NE,
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
	{ TRICORE_INS_ADDC, "addc" },
	{ TRICORE_INS_ADDI, "addi" },
	{ TRICORE_INS_ADDX, "addx" },
	{ TRICORE_INS_ADD_A, "add.a" },
	{ TRICORE_INS_ADD, "add" },
	{ TRICORE_INS_ANDN, "andn" },
	{ TRICORE_INS_AND_EQ, "and.eq" },
	{ TRICORE_INS_AND_GE_U, "and.ge.u" },
	{ TRICORE_INS_AND_GE, "and.ge" },
	{ TRICORE_INS_AND_LT_U, "and.lt.u" },
	{ TRICORE_INS_AND_LT, "and.lt" },
	{ TRICORE_INS_AND_NE, "and.ne" },
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
	{ TRICORE_INS_LD_BU, "ld.bu" },
	{ TRICORE_INS_LD_B, "ld.b" },
	{ TRICORE_INS_LD_D, "ld.d" },
	{ TRICORE_INS_LD_HU, "ld.hu" },
	{ TRICORE_INS_LD_H, "ld.h" },
	{ TRICORE_INS_LD_W, "ld.w" },
	{ TRICORE_INS_LT, "lt" },
	{ TRICORE_INS_MOVH, "movh" },
	{ TRICORE_INS_MOV_AA, "mov.aa" },
	{ TRICORE_INS_MOV_A, "mov.a" },
	{ TRICORE_INS_MOV_D, "mov.d" },
	{ TRICORE_INS_MOV_U, "mov.u" },
	{ TRICORE_INS_MOV, "mov" },
	{ TRICORE_INS_MUL, "mul" },
	{ TRICORE_INS_NAND, "nand" },
	{ TRICORE_INS_NE, "ne" },
	{ TRICORE_INS_NOR, "nor" },
	{ TRICORE_INS_NOT, "not" },
	{ TRICORE_INS_ORN, "orn" },
	{ TRICORE_INS_OR_GE_U, "or.ge.u" },
	{ TRICORE_INS_OR_GE, "or.ge" },
	{ TRICORE_INS_OR_LT_U, "or.lt.u" },
	{ TRICORE_INS_OR_LT, "or.lt" },
	{ TRICORE_INS_OR_NE, "or.ne" },
	{ TRICORE_INS_OR, "or" },
	{ TRICORE_INS_RET, "ret" },
	{ TRICORE_INS_RSUB, "rsub" },
	{ TRICORE_INS_SHA, "sha" },
	{ TRICORE_INS_SH, "sh" },
	{ TRICORE_INS_ST_A, "st.a" },
	{ TRICORE_INS_ST_B, "st.b" },
	{ TRICORE_INS_ST_D, "st.d" },
	{ TRICORE_INS_ST_H, "st.h" },
	{ TRICORE_INS_ST_W, "st.w" },
	{ TRICORE_INS_SUBC, "subc" },
	{ TRICORE_INS_SUBX, "subx" },
	{ TRICORE_INS_SUB_A, "sub.a" },	
	{ TRICORE_INS_SUB, "sub" },
	{ TRICORE_INS_Select8, "select8" },
	{ TRICORE_INS_XNOR, "xnor" },
	{ TRICORE_INS_XOR_GE_U, "xor.ge.u" },
	{ TRICORE_INS_XOR_GE, "xor.ge" },
	{ TRICORE_INS_XOR_LT_U, "xor.lt.u" },
	{ TRICORE_INS_XOR_LT, "xor.lt" },
	{ TRICORE_INS_XOR_NE, "xor.ne" },
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

#ifndef CAPSTONE_DIET
static name_map group_name_maps[] = {
	{ TRICORE_GRP_INVALID, NULL },
	{ TRICORE_GRP_JUMP, "jump" },
};
#endif

const char *TriCore_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= TRICORE_GRP_ENDING)
		return NULL;

	return group_name_maps[id].name;
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
