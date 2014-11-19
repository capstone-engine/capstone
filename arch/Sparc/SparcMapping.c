/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_SPARC

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "SparcMapping.h"

#define GET_INSTRINFO_ENUM
#include "SparcGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static name_map reg_name_maps[] = {
	{ SPARC_REG_INVALID, NULL },

	{ SPARC_REG_F0, "f0"},
	{ SPARC_REG_F1, "f1"},
	{ SPARC_REG_F2, "f2"},
	{ SPARC_REG_F3, "f3"},
	{ SPARC_REG_F4, "f4"},
	{ SPARC_REG_F5, "f5"},
	{ SPARC_REG_F6, "f6"},
	{ SPARC_REG_F7, "f7"},
	{ SPARC_REG_F8, "f8"},
	{ SPARC_REG_F9, "f9"},
	{ SPARC_REG_F10, "f10"},
	{ SPARC_REG_F11, "f11"},
	{ SPARC_REG_F12, "f12"},
	{ SPARC_REG_F13, "f13"},
	{ SPARC_REG_F14, "f14"},
	{ SPARC_REG_F15, "f15"},
	{ SPARC_REG_F16, "f16"},
	{ SPARC_REG_F17, "f17"},
	{ SPARC_REG_F18, "f18"},
	{ SPARC_REG_F19, "f19"},
	{ SPARC_REG_F20, "f20"},
	{ SPARC_REG_F21, "f21"},
	{ SPARC_REG_F22, "f22"},
	{ SPARC_REG_F23, "f23"},
	{ SPARC_REG_F24, "f24"},
	{ SPARC_REG_F25, "f25"},
	{ SPARC_REG_F26, "f26"},
	{ SPARC_REG_F27, "f27"},
	{ SPARC_REG_F28, "f28"},
	{ SPARC_REG_F29, "f29"},
	{ SPARC_REG_F30, "f30"},
	{ SPARC_REG_F31, "f31"},
	{ SPARC_REG_F32, "f32"},
	{ SPARC_REG_F34, "f34"},
	{ SPARC_REG_F36, "f36"},
	{ SPARC_REG_F38, "f38"},
	{ SPARC_REG_F40, "f40"},
	{ SPARC_REG_F42, "f42"},
	{ SPARC_REG_F44, "f44"},
	{ SPARC_REG_F46, "f46"},
	{ SPARC_REG_F48, "f48"},
	{ SPARC_REG_F50, "f50"},
	{ SPARC_REG_F52, "f52"},
	{ SPARC_REG_F54, "f54"},
	{ SPARC_REG_F56, "f56"},
	{ SPARC_REG_F58, "f58"},
	{ SPARC_REG_F60, "f60"},
	{ SPARC_REG_F62, "f62"},
	{ SPARC_REG_FCC0, "fcc0"},
	{ SPARC_REG_FCC1, "fcc1"},
	{ SPARC_REG_FCC2, "fcc2"},
	{ SPARC_REG_FCC3, "fcc3"},
	{ SPARC_REG_FP, "fp"},
	{ SPARC_REG_G0, "g0"},
	{ SPARC_REG_G1, "g1"},
	{ SPARC_REG_G2, "g2"},
	{ SPARC_REG_G3, "g3"},
	{ SPARC_REG_G4, "g4"},
	{ SPARC_REG_G5, "g5"},
	{ SPARC_REG_G6, "g6"},
	{ SPARC_REG_G7, "g7"},
	{ SPARC_REG_I0, "i0"},
	{ SPARC_REG_I1, "i1"},
	{ SPARC_REG_I2, "i2"},
	{ SPARC_REG_I3, "i3"},
	{ SPARC_REG_I4, "i4"},
	{ SPARC_REG_I5, "i5"},
	{ SPARC_REG_I7, "i7"},
	{ SPARC_REG_ICC, "icc"},
	{ SPARC_REG_L0, "l0"},
	{ SPARC_REG_L1, "l1"},
	{ SPARC_REG_L2, "l2"},
	{ SPARC_REG_L3, "l3"},
	{ SPARC_REG_L4, "l4"},
	{ SPARC_REG_L5, "l5"},
	{ SPARC_REG_L6, "l6"},
	{ SPARC_REG_L7, "l7"},
	{ SPARC_REG_O0, "o0"},
	{ SPARC_REG_O1, "o1"},
	{ SPARC_REG_O2, "o2"},
	{ SPARC_REG_O3, "o3"},
	{ SPARC_REG_O4, "o4"},
	{ SPARC_REG_O5, "o5"},
	{ SPARC_REG_O7, "o7"},
	{ SPARC_REG_SP, "sp"},
	{ SPARC_REG_Y, "y"},

	// special registers
	{ SPARC_REG_XCC, "xcc"},
};
#endif

const char *Sparc_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= SPARC_REG_ENDING)
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
		SP_ADDCCri, SPARC_INS_ADDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDCCrr, SPARC_INS_ADDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDCri, SPARC_INS_ADDX,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDCrr, SPARC_INS_ADDX,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDEri, SPARC_INS_ADDXCC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDErr, SPARC_INS_ADDXCC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDXC, SPARC_INS_ADDXC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_ADDXCCC, SPARC_INS_ADDXCCC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { SPARC_REG_ICC, 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_ADDXri, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ADDXrr, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ADDri, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ADDrr, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ALIGNADDR, SPARC_INS_ALIGNADDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_ALIGNADDRL, SPARC_INS_ALIGNADDRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_ANDCCri, SPARC_INS_ANDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDCCrr, SPARC_INS_ANDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDNCCri, SPARC_INS_ANDNCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDNCCrr, SPARC_INS_ANDNCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDNri, SPARC_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDNrr, SPARC_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDXNrr, SPARC_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ANDXri, SPARC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ANDXrr, SPARC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ANDri, SPARC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ANDrr, SPARC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ARRAY16, SPARC_INS_ARRAY16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_ARRAY32, SPARC_INS_ARRAY32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_ARRAY8, SPARC_INS_ARRAY8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_BA, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SP_BCOND, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SP_BCONDA, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SP_BINDri, SPARC_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		SP_BINDrr, SPARC_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		SP_BMASK, SPARC_INS_BMASK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_BPFCC, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPFCCA, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPFCCANT, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPFCCNT, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPGEZapn, SPARC_INS_BRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGEZapt, SPARC_INS_BRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGEZnapn, SPARC_INS_BRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGEZnapt, SPARC_INS_BRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGZapn, SPARC_INS_BRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGZapt, SPARC_INS_BRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGZnapn, SPARC_INS_BRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPGZnapt, SPARC_INS_BRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPICC, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPICCA, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPICCANT, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPICCNT, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 1, 0
#endif
	},
	{
		SP_BPLEZapn, SPARC_INS_BRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLEZapt, SPARC_INS_BRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLEZnapn, SPARC_INS_BRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLEZnapt, SPARC_INS_BRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLZapn, SPARC_INS_BRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLZapt, SPARC_INS_BRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLZnapn, SPARC_INS_BRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPLZnapt, SPARC_INS_BRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPNZapn, SPARC_INS_BRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPNZapt, SPARC_INS_BRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPNZnapn, SPARC_INS_BRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPNZnapt, SPARC_INS_BRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPXCC, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPXCCA, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPXCCANT, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPXCCNT, SPARC_INS_B,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPZapn, SPARC_INS_BRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPZapt, SPARC_INS_BRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPZnapn, SPARC_INS_BRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BPZnapt, SPARC_INS_BRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 1, 0
#endif
	},
	{
		SP_BSHUFFLE, SPARC_INS_BSHUFFLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_CALL, SPARC_INS_CALL,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_O6, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_CALLri, SPARC_INS_CALL,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_O6, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_CALLrr, SPARC_INS_CALL,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_O6, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_CASXrr, SPARC_INS_CASX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_CASrr, SPARC_INS_CAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_CMASK16, SPARC_INS_CMASK16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_CMASK32, SPARC_INS_CMASK32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_CMASK8, SPARC_INS_CMASK8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_CMPri, SPARC_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_CMPrr, SPARC_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_EDGE16, SPARC_INS_EDGE16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE16L, SPARC_INS_EDGE16L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE16LN, SPARC_INS_EDGE16LN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE16N, SPARC_INS_EDGE16N,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE32, SPARC_INS_EDGE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE32L, SPARC_INS_EDGE32L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE32LN, SPARC_INS_EDGE32LN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE32N, SPARC_INS_EDGE32N,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE8, SPARC_INS_EDGE8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE8L, SPARC_INS_EDGE8L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE8LN, SPARC_INS_EDGE8LN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_EDGE8N, SPARC_INS_EDGE8N,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_FABSD, SPARC_INS_FABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FABSQ, SPARC_INS_FABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FABSS, SPARC_INS_FABSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FADDD, SPARC_INS_FADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FADDQ, SPARC_INS_FADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FADDS, SPARC_INS_FADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FALIGNADATA, SPARC_INS_FALIGNDATA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FAND, SPARC_INS_FAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FANDNOT1, SPARC_INS_FANDNOT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FANDNOT1S, SPARC_INS_FANDNOT1S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FANDNOT2, SPARC_INS_FANDNOT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FANDNOT2S, SPARC_INS_FANDNOT2S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FANDS, SPARC_INS_FANDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FBCOND, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SP_FBCONDA, SPARC_INS_FB,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SP_FCHKSM16, SPARC_INS_FCHKSM16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPD, SPARC_INS_FCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_FCC0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FCMPEQ16, SPARC_INS_FCMPEQ16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPEQ32, SPARC_INS_FCMPEQ32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPGT16, SPARC_INS_FCMPGT16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPGT32, SPARC_INS_FCMPGT32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPLE16, SPARC_INS_FCMPLE16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPLE32, SPARC_INS_FCMPLE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPNE16, SPARC_INS_FCMPNE16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPNE32, SPARC_INS_FCMPNE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPQ, SPARC_INS_FCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_FCC0, 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FCMPS, SPARC_INS_FCMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_FCC0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FDIVD, SPARC_INS_FDIVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FDIVQ, SPARC_INS_FDIVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FDIVS, SPARC_INS_FDIVS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FDMULQ, SPARC_INS_FDMULQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FDTOI, SPARC_INS_FDTOI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FDTOQ, SPARC_INS_FDTOQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FDTOS, SPARC_INS_FDTOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FDTOX, SPARC_INS_FDTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FEXPAND, SPARC_INS_FEXPAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FHADDD, SPARC_INS_FHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FHADDS, SPARC_INS_FHADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FHSUBD, SPARC_INS_FHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FHSUBS, SPARC_INS_FHSUBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FITOD, SPARC_INS_FITOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FITOQ, SPARC_INS_FITOQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FITOS, SPARC_INS_FITOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FLCMPD, SPARC_INS_FLCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FLCMPS, SPARC_INS_FLCMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FLUSHW, SPARC_INS_FLUSHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMEAN16, SPARC_INS_FMEAN16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVD, SPARC_INS_FMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVD_FCC, SPARC_INS_FMOVD,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVD_ICC, SPARC_INS_FMOVD,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVD_XCC, SPARC_INS_FMOVD,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVQ, SPARC_INS_FMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVQ_FCC, SPARC_INS_FMOVQ,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVQ_ICC, SPARC_INS_FMOVQ,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVQ_XCC, SPARC_INS_FMOVQ,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGEZD, SPARC_INS_FMOVRDGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGEZQ, SPARC_INS_FMOVRQGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGEZS, SPARC_INS_FMOVRSGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGZD, SPARC_INS_FMOVRDGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGZQ, SPARC_INS_FMOVRQGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRGZS, SPARC_INS_FMOVRSGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLEZD, SPARC_INS_FMOVRDLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLEZQ, SPARC_INS_FMOVRQLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLEZS, SPARC_INS_FMOVRSLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLZD, SPARC_INS_FMOVRDLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLZQ, SPARC_INS_FMOVRQLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRLZS, SPARC_INS_FMOVRSLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRNZD, SPARC_INS_FMOVRDNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRNZQ, SPARC_INS_FMOVRQNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRNZS, SPARC_INS_FMOVRSNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRZD, SPARC_INS_FMOVRDZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRZQ, SPARC_INS_FMOVRQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVRZS, SPARC_INS_FMOVRSZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVS, SPARC_INS_FMOVS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FMOVS_FCC, SPARC_INS_FMOVS,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVS_ICC, SPARC_INS_FMOVS,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FMOVS_XCC, SPARC_INS_FMOVS,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FMUL8SUX16, SPARC_INS_FMUL8SUX16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMUL8ULX16, SPARC_INS_FMUL8ULX16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMUL8X16, SPARC_INS_FMUL8X16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMUL8X16AL, SPARC_INS_FMUL8X16AL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMUL8X16AU, SPARC_INS_FMUL8X16AU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMULD, SPARC_INS_FMULD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FMULD8SUX16, SPARC_INS_FMULD8SUX16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMULD8ULX16, SPARC_INS_FMULD8ULX16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FMULQ, SPARC_INS_FMULQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FMULS, SPARC_INS_FMULS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FNADDD, SPARC_INS_FNADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNADDS, SPARC_INS_FNADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNAND, SPARC_INS_FNAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNANDS, SPARC_INS_FNANDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNEGD, SPARC_INS_FNEGD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FNEGQ, SPARC_INS_FNEGQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_FNEGS, SPARC_INS_FNEGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FNHADDD, SPARC_INS_FNHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNHADDS, SPARC_INS_FNHADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNMULD, SPARC_INS_FNHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNMULS, SPARC_INS_FNHADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FNOR, SPARC_INS_FNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNORS, SPARC_INS_FNORS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNOT1, SPARC_INS_FNOT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNOT1S, SPARC_INS_FNOT1S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNOT2, SPARC_INS_FNOT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNOT2S, SPARC_INS_FNOT2S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FNSMULD, SPARC_INS_FNHADDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FONE, SPARC_INS_FONE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FONES, SPARC_INS_FONES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FOR, SPARC_INS_FOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FORNOT1, SPARC_INS_FORNOT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FORNOT1S, SPARC_INS_FORNOT1S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FORNOT2, SPARC_INS_FORNOT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FORNOT2S, SPARC_INS_FORNOT2S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FORS, SPARC_INS_FORS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPACK16, SPARC_INS_FPACK16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPACK32, SPARC_INS_FPACK32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPACKFIX, SPARC_INS_FPACKFIX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPADD16, SPARC_INS_FPADD16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPADD16S, SPARC_INS_FPADD16S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPADD32, SPARC_INS_FPADD32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPADD32S, SPARC_INS_FPADD32S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPADD64, SPARC_INS_FPADD64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FPMERGE, SPARC_INS_FPMERGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPSUB16, SPARC_INS_FPSUB16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPSUB16S, SPARC_INS_FPSUB16S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPSUB32, SPARC_INS_FPSUB32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FPSUB32S, SPARC_INS_FPSUB32S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FQTOD, SPARC_INS_FQTOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FQTOI, SPARC_INS_FQTOI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FQTOS, SPARC_INS_FQTOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FQTOX, SPARC_INS_FQTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FSLAS16, SPARC_INS_FSLAS16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSLAS32, SPARC_INS_FSLAS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSLL16, SPARC_INS_FSLL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSLL32, SPARC_INS_FSLL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSMULD, SPARC_INS_FSMULD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSQRTD, SPARC_INS_FSQRTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSQRTQ, SPARC_INS_FSQRTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FSQRTS, SPARC_INS_FSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSRA16, SPARC_INS_FSRA16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSRA32, SPARC_INS_FSRA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSRC1, SPARC_INS_FSRC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FSRC1S, SPARC_INS_FSRC1S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FSRC2, SPARC_INS_FSRC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FSRC2S, SPARC_INS_FSRC2S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FSRL16, SPARC_INS_FSRL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSRL32, SPARC_INS_FSRL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_FSTOD, SPARC_INS_FSTOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSTOI, SPARC_INS_FSTOI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSTOQ, SPARC_INS_FSTOQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FSTOX, SPARC_INS_FSTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FSUBD, SPARC_INS_FSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FSUBQ, SPARC_INS_FSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_FSUBS, SPARC_INS_FSUBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_FXNOR, SPARC_INS_FXNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FXNORS, SPARC_INS_FXNORS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FXOR, SPARC_INS_FXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FXORS, SPARC_INS_FXORS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FXTOD, SPARC_INS_FXTOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FXTOQ, SPARC_INS_FXTOQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FXTOS, SPARC_INS_FXTOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_FZERO, SPARC_INS_FZERO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_FZEROS, SPARC_INS_FZEROS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_JMPLri, SPARC_INS_JMPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_JMPLrr, SPARC_INS_JMPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDDFri, SPARC_INS_LDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDDFrr, SPARC_INS_LDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDFri, SPARC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDFrr, SPARC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDQFri, SPARC_INS_LDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_LDQFrr, SPARC_INS_LDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_LDSBri, SPARC_INS_LDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDSBrr, SPARC_INS_LDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDSHri, SPARC_INS_LDSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDSHrr, SPARC_INS_LDSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDSWri, SPARC_INS_LDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LDSWrr, SPARC_INS_LDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LDUBri, SPARC_INS_LDUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDUBrr, SPARC_INS_LDUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDUHri, SPARC_INS_LDUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDUHrr, SPARC_INS_LDUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDXri, SPARC_INS_LDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LDXrr, SPARC_INS_LDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LDri, SPARC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LDrr, SPARC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_LEAX_ADDri, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LEA_ADDri, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_32BIT, 0 }, 0, 0
#endif
	},
	{
		SP_LZCNT, SPARC_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MEMBARi, SPARC_INS_MEMBAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_MOVDTOX, SPARC_INS_MOVDTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MOVFCCri, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_MOVFCCrr, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_FCC0, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_MOVICCri, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_MOVICCrr, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRGEZri, SPARC_INS_MOVRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRGEZrr, SPARC_INS_MOVRGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRGZri, SPARC_INS_MOVRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRGZrr, SPARC_INS_MOVRGZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRLEZri, SPARC_INS_MOVRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRLEZrr, SPARC_INS_MOVRLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRLZri, SPARC_INS_MOVRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRLZrr, SPARC_INS_MOVRLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRNZri, SPARC_INS_MOVRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRNZrr, SPARC_INS_MOVRNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRRZri, SPARC_INS_MOVRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVRRZrr, SPARC_INS_MOVRZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVSTOSW, SPARC_INS_MOVSTOSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MOVSTOUW, SPARC_INS_MOVSTOUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MOVWTOS, SPARC_INS_MOVDTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MOVXCCri, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVXCCrr, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MOVXTOD, SPARC_INS_MOVDTOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_MULXri, SPARC_INS_MULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_MULXrr, SPARC_INS_MULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_NOP, SPARC_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORCCri, SPARC_INS_ORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORCCrr, SPARC_INS_ORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORNCCri, SPARC_INS_ORNCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORNCCrr, SPARC_INS_ORNCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORNri, SPARC_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORNrr, SPARC_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORXNrr, SPARC_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ORXri, SPARC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ORXrr, SPARC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_ORri, SPARC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_ORrr, SPARC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_PDIST, SPARC_INS_PDIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_PDISTN, SPARC_INS_PDISTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_POPCrr, SPARC_INS_POPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_RDY, SPARC_INS_RD,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_Y, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RESTOREri, SPARC_INS_RESTORE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RESTORErr, SPARC_INS_RESTORE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RET, SPARC_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RETL, SPARC_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RETTri, SPARC_INS_RETT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_RETTrr, SPARC_INS_RETT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SAVEri, SPARC_INS_SAVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SAVErr, SPARC_INS_SAVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SDIVCCri, SPARC_INS_SDIVCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SDIVCCrr, SPARC_INS_SDIVCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SDIVXri, SPARC_INS_SDIVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SDIVXrr, SPARC_INS_SDIVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SDIVri, SPARC_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SDIVrr, SPARC_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SETHIXi, SPARC_INS_SETHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SETHIi, SPARC_INS_SETHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SHUTDOWN, SPARC_INS_SHUTDOWN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS, 0 }, 0, 0
#endif
	},
	{
		SP_SIAM, SPARC_INS_SIAM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS2, 0 }, 0, 0
#endif
	},
	{
		SP_SLLXri, SPARC_INS_SLLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SLLXrr, SPARC_INS_SLLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SLLri, SPARC_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SLLrr, SPARC_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SMULCCri, SPARC_INS_SMULCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SMULCCrr, SPARC_INS_SMULCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SMULri, SPARC_INS_SMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SMULrr, SPARC_INS_SMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SRAXri, SPARC_INS_SRAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SRAXrr, SPARC_INS_SRAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SRAri, SPARC_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SRArr, SPARC_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SRLXri, SPARC_INS_SRLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SRLXrr, SPARC_INS_SRLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SRLri, SPARC_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SRLrr, SPARC_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STBAR, SPARC_INS_STBAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STBri, SPARC_INS_STB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STBrr, SPARC_INS_STB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STDFri, SPARC_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STDFrr, SPARC_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STFri, SPARC_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STFrr, SPARC_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STHri, SPARC_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STHrr, SPARC_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STQFri, SPARC_INS_STQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_STQFrr, SPARC_INS_STQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_STXri, SPARC_INS_STX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_STXrr, SPARC_INS_STX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_STri, SPARC_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_STrr, SPARC_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBCCri, SPARC_INS_SUBCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBCCrr, SPARC_INS_SUBCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBCri, SPARC_INS_SUBX,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBCrr, SPARC_INS_SUBX,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBEri, SPARC_INS_SUBXCC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBErr, SPARC_INS_SUBXCC,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBXri, SPARC_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SUBXrr, SPARC_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_SUBri, SPARC_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SUBrr, SPARC_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SWAPri, SPARC_INS_SWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_SWAPrr, SPARC_INS_SWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TA3, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TA5, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TADDCCTVri, SPARC_INS_TADDCCTV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TADDCCTVrr, SPARC_INS_TADDCCTV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TADDCCri, SPARC_INS_TADDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TADDCCrr, SPARC_INS_TADDCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TICCri, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TICCrr, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TLS_ADDXrr, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_TLS_ADDrr, SPARC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TLS_CALL, SPARC_INS_CALL,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_O6, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TLS_LDXrr, SPARC_INS_LDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_TLS_LDrr, SPARC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TSUBCCTVri, SPARC_INS_TSUBCCTV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TSUBCCTVrr, SPARC_INS_TSUBCCTV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TSUBCCri, SPARC_INS_TSUBCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TSUBCCrr, SPARC_INS_TSUBCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_TXCCri, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_TXCCrr, SPARC_INS_T,
#ifndef CAPSTONE_DIET
		{ SPARC_REG_ICC, 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_UDIVCCri, SPARC_INS_UDIVCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UDIVCCrr, SPARC_INS_UDIVCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UDIVXri, SPARC_INS_UDIVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_UDIVXrr, SPARC_INS_UDIVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_UDIVri, SPARC_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UDIVrr, SPARC_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UMULCCri, SPARC_INS_UMULCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UMULCCrr, SPARC_INS_UMULCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UMULXHI, SPARC_INS_UMULXHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_UMULri, SPARC_INS_UMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UMULrr, SPARC_INS_UMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_UNIMP, SPARC_INS_UNIMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPD, SPARC_INS_FCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPED, SPARC_INS_FCMPED,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPEQ, SPARC_INS_FCMPEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPES, SPARC_INS_FCMPES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPQ, SPARC_INS_FCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_HARDQUAD, 0 }, 0, 0
#endif
	},
	{
		SP_V9FCMPS, SPARC_INS_FCMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_V9FMOVD_FCC, SPARC_INS_FMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_V9FMOVQ_FCC, SPARC_INS_FMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_V9FMOVS_FCC, SPARC_INS_FMOVS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_V9MOVFCCri, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_V9MOVFCCrr, SPARC_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_V9, 0 }, 0, 0
#endif
	},
	{
		SP_WRYri, SPARC_INS_WR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_WRYrr, SPARC_INS_WR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_Y, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XMULX, SPARC_INS_XMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_XMULXHI, SPARC_INS_XMULXHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_VIS3, 0 }, 0, 0
#endif
	},
	{
		SP_XNORCCri, SPARC_INS_XNORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XNORCCrr, SPARC_INS_XNORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XNORXrr, SPARC_INS_XNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_XNORri, SPARC_INS_XNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XNORrr, SPARC_INS_XNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XORCCri, SPARC_INS_XORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XORCCrr, SPARC_INS_XORCC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SPARC_REG_ICC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XORXri, SPARC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_XORXrr, SPARC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SPARC_GRP_64BIT, 0 }, 0, 0
#endif
	},
	{
		SP_XORri, SPARC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SP_XORrr, SPARC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
};

static struct hint_map {
	unsigned int id;
	uint8_t hints;
} insn_hints[] = {
	{ SP_BPGEZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPGEZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPGEZnapn, SPARC_HINT_PN },
	{ SP_BPGZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPGZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPGZnapn, SPARC_HINT_PN },
	{ SP_BPLEZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPLEZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPLEZnapn, SPARC_HINT_PN },
	{ SP_BPLZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPLZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPLZnapn, SPARC_HINT_PN },
	{ SP_BPNZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPNZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPNZnapn, SPARC_HINT_PN },
	{ SP_BPZapn, SPARC_HINT_A | SPARC_HINT_PN },
	{ SP_BPZapt, SPARC_HINT_A | SPARC_HINT_PT },
	{ SP_BPZnapn, SPARC_HINT_PN },
};

// given internal insn id, return public instruction info
void Sparc_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
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
				insn->detail->groups[insn->detail->groups_count] = SPARC_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
			// hint code
			for (i = 0; i < ARR_SIZE(insn_hints); i++) {
				if (id == insn_hints[i].id) {
					insn->detail->sparc.hint = insn_hints[i].hints;
					break;
				}
			}
		}
	}
}

static name_map insn_name_maps[] = {
	{ SPARC_INS_INVALID, NULL },

	{ SPARC_INS_ADDCC, "addcc" },
	{ SPARC_INS_ADDX, "addx" },
	{ SPARC_INS_ADDXCC, "addxcc" },
	{ SPARC_INS_ADDXC, "addxc" },
	{ SPARC_INS_ADDXCCC, "addxccc" },
	{ SPARC_INS_ADD, "add" },
	{ SPARC_INS_ALIGNADDR, "alignaddr" },
	{ SPARC_INS_ALIGNADDRL, "alignaddrl" },
	{ SPARC_INS_ANDCC, "andcc" },
	{ SPARC_INS_ANDNCC, "andncc" },
	{ SPARC_INS_ANDN, "andn" },
	{ SPARC_INS_AND, "and" },
	{ SPARC_INS_ARRAY16, "array16" },
	{ SPARC_INS_ARRAY32, "array32" },
	{ SPARC_INS_ARRAY8, "array8" },
	{ SPARC_INS_B, "b" },
	{ SPARC_INS_JMP, "jmp" },
	{ SPARC_INS_BMASK, "bmask" },
	{ SPARC_INS_FB, "fb" },
	{ SPARC_INS_BRGEZ, "brgez" },
	{ SPARC_INS_BRGZ, "brgz" },
	{ SPARC_INS_BRLEZ, "brlez" },
	{ SPARC_INS_BRLZ, "brlz" },
	{ SPARC_INS_BRNZ, "brnz" },
	{ SPARC_INS_BRZ, "brz" },
	{ SPARC_INS_BSHUFFLE, "bshuffle" },
	{ SPARC_INS_CALL, "call" },
	{ SPARC_INS_CASX, "casx" },
	{ SPARC_INS_CAS, "cas" },
	{ SPARC_INS_CMASK16, "cmask16" },
	{ SPARC_INS_CMASK32, "cmask32" },
	{ SPARC_INS_CMASK8, "cmask8" },
	{ SPARC_INS_CMP, "cmp" },
	{ SPARC_INS_EDGE16, "edge16" },
	{ SPARC_INS_EDGE16L, "edge16l" },
	{ SPARC_INS_EDGE16LN, "edge16ln" },
	{ SPARC_INS_EDGE16N, "edge16n" },
	{ SPARC_INS_EDGE32, "edge32" },
	{ SPARC_INS_EDGE32L, "edge32l" },
	{ SPARC_INS_EDGE32LN, "edge32ln" },
	{ SPARC_INS_EDGE32N, "edge32n" },
	{ SPARC_INS_EDGE8, "edge8" },
	{ SPARC_INS_EDGE8L, "edge8l" },
	{ SPARC_INS_EDGE8LN, "edge8ln" },
	{ SPARC_INS_EDGE8N, "edge8n" },
	{ SPARC_INS_FABSD, "fabsd" },
	{ SPARC_INS_FABSQ, "fabsq" },
	{ SPARC_INS_FABSS, "fabss" },
	{ SPARC_INS_FADDD, "faddd" },
	{ SPARC_INS_FADDQ, "faddq" },
	{ SPARC_INS_FADDS, "fadds" },
	{ SPARC_INS_FALIGNDATA, "faligndata" },
	{ SPARC_INS_FAND, "fand" },
	{ SPARC_INS_FANDNOT1, "fandnot1" },
	{ SPARC_INS_FANDNOT1S, "fandnot1s" },
	{ SPARC_INS_FANDNOT2, "fandnot2" },
	{ SPARC_INS_FANDNOT2S, "fandnot2s" },
	{ SPARC_INS_FANDS, "fands" },
	{ SPARC_INS_FCHKSM16, "fchksm16" },
	{ SPARC_INS_FCMPD, "fcmpd" },
	{ SPARC_INS_FCMPEQ16, "fcmpeq16" },
	{ SPARC_INS_FCMPEQ32, "fcmpeq32" },
	{ SPARC_INS_FCMPGT16, "fcmpgt16" },
	{ SPARC_INS_FCMPGT32, "fcmpgt32" },
	{ SPARC_INS_FCMPLE16, "fcmple16" },
	{ SPARC_INS_FCMPLE32, "fcmple32" },
	{ SPARC_INS_FCMPNE16, "fcmpne16" },
	{ SPARC_INS_FCMPNE32, "fcmpne32" },
	{ SPARC_INS_FCMPQ, "fcmpq" },
	{ SPARC_INS_FCMPS, "fcmps" },
	{ SPARC_INS_FDIVD, "fdivd" },
	{ SPARC_INS_FDIVQ, "fdivq" },
	{ SPARC_INS_FDIVS, "fdivs" },
	{ SPARC_INS_FDMULQ, "fdmulq" },
	{ SPARC_INS_FDTOI, "fdtoi" },
	{ SPARC_INS_FDTOQ, "fdtoq" },
	{ SPARC_INS_FDTOS, "fdtos" },
	{ SPARC_INS_FDTOX, "fdtox" },
	{ SPARC_INS_FEXPAND, "fexpand" },
	{ SPARC_INS_FHADDD, "fhaddd" },
	{ SPARC_INS_FHADDS, "fhadds" },
	{ SPARC_INS_FHSUBD, "fhsubd" },
	{ SPARC_INS_FHSUBS, "fhsubs" },
	{ SPARC_INS_FITOD, "fitod" },
	{ SPARC_INS_FITOQ, "fitoq" },
	{ SPARC_INS_FITOS, "fitos" },
	{ SPARC_INS_FLCMPD, "flcmpd" },
	{ SPARC_INS_FLCMPS, "flcmps" },
	{ SPARC_INS_FLUSHW, "flushw" },
	{ SPARC_INS_FMEAN16, "fmean16" },
	{ SPARC_INS_FMOVD, "fmovd" },
	{ SPARC_INS_FMOVQ, "fmovq" },
	{ SPARC_INS_FMOVRDGEZ, "fmovrdgez" },
	{ SPARC_INS_FMOVRQGEZ, "fmovrqgez" },
	{ SPARC_INS_FMOVRSGEZ, "fmovrsgez" },
	{ SPARC_INS_FMOVRDGZ, "fmovrdgz" },
	{ SPARC_INS_FMOVRQGZ, "fmovrqgz" },
	{ SPARC_INS_FMOVRSGZ, "fmovrsgz" },
	{ SPARC_INS_FMOVRDLEZ, "fmovrdlez" },
	{ SPARC_INS_FMOVRQLEZ, "fmovrqlez" },
	{ SPARC_INS_FMOVRSLEZ, "fmovrslez" },
	{ SPARC_INS_FMOVRDLZ, "fmovrdlz" },
	{ SPARC_INS_FMOVRQLZ, "fmovrqlz" },
	{ SPARC_INS_FMOVRSLZ, "fmovrslz" },
	{ SPARC_INS_FMOVRDNZ, "fmovrdnz" },
	{ SPARC_INS_FMOVRQNZ, "fmovrqnz" },
	{ SPARC_INS_FMOVRSNZ, "fmovrsnz" },
	{ SPARC_INS_FMOVRDZ, "fmovrdz" },
	{ SPARC_INS_FMOVRQZ, "fmovrqz" },
	{ SPARC_INS_FMOVRSZ, "fmovrsz" },
	{ SPARC_INS_FMOVS, "fmovs" },
	{ SPARC_INS_FMUL8SUX16, "fmul8sux16" },
	{ SPARC_INS_FMUL8ULX16, "fmul8ulx16" },
	{ SPARC_INS_FMUL8X16, "fmul8x16" },
	{ SPARC_INS_FMUL8X16AL, "fmul8x16al" },
	{ SPARC_INS_FMUL8X16AU, "fmul8x16au" },
	{ SPARC_INS_FMULD, "fmuld" },
	{ SPARC_INS_FMULD8SUX16, "fmuld8sux16" },
	{ SPARC_INS_FMULD8ULX16, "fmuld8ulx16" },
	{ SPARC_INS_FMULQ, "fmulq" },
	{ SPARC_INS_FMULS, "fmuls" },
	{ SPARC_INS_FNADDD, "fnaddd" },
	{ SPARC_INS_FNADDS, "fnadds" },
	{ SPARC_INS_FNAND, "fnand" },
	{ SPARC_INS_FNANDS, "fnands" },
	{ SPARC_INS_FNEGD, "fnegd" },
	{ SPARC_INS_FNEGQ, "fnegq" },
	{ SPARC_INS_FNEGS, "fnegs" },
	{ SPARC_INS_FNHADDD, "fnhaddd" },
	{ SPARC_INS_FNHADDS, "fnhadds" },
	{ SPARC_INS_FNOR, "fnor" },
	{ SPARC_INS_FNORS, "fnors" },
	{ SPARC_INS_FNOT1, "fnot1" },
	{ SPARC_INS_FNOT1S, "fnot1s" },
	{ SPARC_INS_FNOT2, "fnot2" },
	{ SPARC_INS_FNOT2S, "fnot2s" },
	{ SPARC_INS_FONE, "fone" },
	{ SPARC_INS_FONES, "fones" },
	{ SPARC_INS_FOR, "for" },
	{ SPARC_INS_FORNOT1, "fornot1" },
	{ SPARC_INS_FORNOT1S, "fornot1s" },
	{ SPARC_INS_FORNOT2, "fornot2" },
	{ SPARC_INS_FORNOT2S, "fornot2s" },
	{ SPARC_INS_FORS, "fors" },
	{ SPARC_INS_FPACK16, "fpack16" },
	{ SPARC_INS_FPACK32, "fpack32" },
	{ SPARC_INS_FPACKFIX, "fpackfix" },
	{ SPARC_INS_FPADD16, "fpadd16" },
	{ SPARC_INS_FPADD16S, "fpadd16s" },
	{ SPARC_INS_FPADD32, "fpadd32" },
	{ SPARC_INS_FPADD32S, "fpadd32s" },
	{ SPARC_INS_FPADD64, "fpadd64" },
	{ SPARC_INS_FPMERGE, "fpmerge" },
	{ SPARC_INS_FPSUB16, "fpsub16" },
	{ SPARC_INS_FPSUB16S, "fpsub16s" },
	{ SPARC_INS_FPSUB32, "fpsub32" },
	{ SPARC_INS_FPSUB32S, "fpsub32s" },
	{ SPARC_INS_FQTOD, "fqtod" },
	{ SPARC_INS_FQTOI, "fqtoi" },
	{ SPARC_INS_FQTOS, "fqtos" },
	{ SPARC_INS_FQTOX, "fqtox" },
	{ SPARC_INS_FSLAS16, "fslas16" },
	{ SPARC_INS_FSLAS32, "fslas32" },
	{ SPARC_INS_FSLL16, "fsll16" },
	{ SPARC_INS_FSLL32, "fsll32" },
	{ SPARC_INS_FSMULD, "fsmuld" },
	{ SPARC_INS_FSQRTD, "fsqrtd" },
	{ SPARC_INS_FSQRTQ, "fsqrtq" },
	{ SPARC_INS_FSQRTS, "fsqrts" },
	{ SPARC_INS_FSRA16, "fsra16" },
	{ SPARC_INS_FSRA32, "fsra32" },
	{ SPARC_INS_FSRC1, "fsrc1" },
	{ SPARC_INS_FSRC1S, "fsrc1s" },
	{ SPARC_INS_FSRC2, "fsrc2" },
	{ SPARC_INS_FSRC2S, "fsrc2s" },
	{ SPARC_INS_FSRL16, "fsrl16" },
	{ SPARC_INS_FSRL32, "fsrl32" },
	{ SPARC_INS_FSTOD, "fstod" },
	{ SPARC_INS_FSTOI, "fstoi" },
	{ SPARC_INS_FSTOQ, "fstoq" },
	{ SPARC_INS_FSTOX, "fstox" },
	{ SPARC_INS_FSUBD, "fsubd" },
	{ SPARC_INS_FSUBQ, "fsubq" },
	{ SPARC_INS_FSUBS, "fsubs" },
	{ SPARC_INS_FXNOR, "fxnor" },
	{ SPARC_INS_FXNORS, "fxnors" },
	{ SPARC_INS_FXOR, "fxor" },
	{ SPARC_INS_FXORS, "fxors" },
	{ SPARC_INS_FXTOD, "fxtod" },
	{ SPARC_INS_FXTOQ, "fxtoq" },
	{ SPARC_INS_FXTOS, "fxtos" },
	{ SPARC_INS_FZERO, "fzero" },
	{ SPARC_INS_FZEROS, "fzeros" },
	{ SPARC_INS_JMPL, "jmpl" },
	{ SPARC_INS_LDD, "ldd" },
	{ SPARC_INS_LD, "ld" },
	{ SPARC_INS_LDQ, "ldq" },
	{ SPARC_INS_LDSB, "ldsb" },
	{ SPARC_INS_LDSH, "ldsh" },
	{ SPARC_INS_LDSW, "ldsw" },
	{ SPARC_INS_LDUB, "ldub" },
	{ SPARC_INS_LDUH, "lduh" },
	{ SPARC_INS_LDX, "ldx" },
	{ SPARC_INS_LZCNT, "lzcnt" },
	{ SPARC_INS_MEMBAR, "membar" },
	{ SPARC_INS_MOVDTOX, "movdtox" },
	{ SPARC_INS_MOV, "mov" },
	{ SPARC_INS_MOVRGEZ, "movrgez" },
	{ SPARC_INS_MOVRGZ, "movrgz" },
	{ SPARC_INS_MOVRLEZ, "movrlez" },
	{ SPARC_INS_MOVRLZ, "movrlz" },
	{ SPARC_INS_MOVRNZ, "movrnz" },
	{ SPARC_INS_MOVRZ, "movrz" },
	{ SPARC_INS_MOVSTOSW, "movstosw" },
	{ SPARC_INS_MOVSTOUW, "movstouw" },
	{ SPARC_INS_MULX, "mulx" },
	{ SPARC_INS_NOP, "nop" },
	{ SPARC_INS_ORCC, "orcc" },
	{ SPARC_INS_ORNCC, "orncc" },
	{ SPARC_INS_ORN, "orn" },
	{ SPARC_INS_OR, "or" },
	{ SPARC_INS_PDIST, "pdist" },
	{ SPARC_INS_PDISTN, "pdistn" },
	{ SPARC_INS_POPC, "popc" },
	{ SPARC_INS_RD, "rd" },
	{ SPARC_INS_RESTORE, "restore" },
	{ SPARC_INS_RETT, "rett" },
	{ SPARC_INS_SAVE, "save" },
	{ SPARC_INS_SDIVCC, "sdivcc" },
	{ SPARC_INS_SDIVX, "sdivx" },
	{ SPARC_INS_SDIV, "sdiv" },
	{ SPARC_INS_SETHI, "sethi" },
	{ SPARC_INS_SHUTDOWN, "shutdown" },
	{ SPARC_INS_SIAM, "siam" },
	{ SPARC_INS_SLLX, "sllx" },
	{ SPARC_INS_SLL, "sll" },
	{ SPARC_INS_SMULCC, "smulcc" },
	{ SPARC_INS_SMUL, "smul" },
	{ SPARC_INS_SRAX, "srax" },
	{ SPARC_INS_SRA, "sra" },
	{ SPARC_INS_SRLX, "srlx" },
	{ SPARC_INS_SRL, "srl" },
	{ SPARC_INS_STBAR, "stbar" },
	{ SPARC_INS_STB, "stb" },
	{ SPARC_INS_STD, "std" },
	{ SPARC_INS_ST, "st" },
	{ SPARC_INS_STH, "sth" },
	{ SPARC_INS_STQ, "stq" },
	{ SPARC_INS_STX, "stx" },
	{ SPARC_INS_SUBCC, "subcc" },
	{ SPARC_INS_SUBX, "subx" },
	{ SPARC_INS_SUBXCC, "subxcc" },
	{ SPARC_INS_SUB, "sub" },
	{ SPARC_INS_SWAP, "swap" },
	{ SPARC_INS_TADDCCTV, "taddcctv" },
	{ SPARC_INS_TADDCC, "taddcc" },
	{ SPARC_INS_T, "t" },
	{ SPARC_INS_TSUBCCTV, "tsubcctv" },
	{ SPARC_INS_TSUBCC, "tsubcc" },
	{ SPARC_INS_UDIVCC, "udivcc" },
	{ SPARC_INS_UDIVX, "udivx" },
	{ SPARC_INS_UDIV, "udiv" },
	{ SPARC_INS_UMULCC, "umulcc" },
	{ SPARC_INS_UMULXHI, "umulxhi" },
	{ SPARC_INS_UMUL, "umul" },
	{ SPARC_INS_UNIMP, "unimp" },
	{ SPARC_INS_FCMPED, "fcmped" },
	{ SPARC_INS_FCMPEQ, "fcmpeq" },
	{ SPARC_INS_FCMPES, "fcmpes" },
	{ SPARC_INS_WR, "wr" },
	{ SPARC_INS_XMULX, "xmulx" },
	{ SPARC_INS_XMULXHI, "xmulxhi" },
	{ SPARC_INS_XNORCC, "xnorcc" },
	{ SPARC_INS_XNOR, "xnor" },
	{ SPARC_INS_XORCC, "xorcc" },
	{ SPARC_INS_XOR, "xor" },

	// alias instructions
	{ SPARC_INS_RET, "ret" },
	{ SPARC_INS_RETL, "retl" },
};

#ifndef CAPSTONE_DIET
// special alias insn
static name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *Sparc_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= SPARC_INS_ENDING)
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
	// generic groups
	{ SPARC_GRP_INVALID, NULL },
	{ SPARC_GRP_JUMP, "jump" },

	// architecture-specific groups
	{ SPARC_GRP_HARDQUAD, "hardquad" },
	{ SPARC_GRP_V9, "v9" },
	{ SPARC_GRP_VIS, "vis" },
	{ SPARC_GRP_VIS2, "vis2" },
	{ SPARC_GRP_VIS3,  "vis3" },
	{ SPARC_GRP_32BIT, "32bit" },
	{ SPARC_GRP_64BIT, "64bit" },
};
#endif

const char *Sparc_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= SPARC_GRP_ENDING || (id > SPARC_GRP_JUMP && id < SPARC_GRP_HARDQUAD))
		return NULL;

	// NOTE: when new generic groups are added, 2 must be changed accordingly
	if (id >= 128)
		return group_name_maps[id - 128 + 2].name;
	else
		return group_name_maps[id].name;
#else
	return NULL;
#endif
}

// map internal raw register to 'public' register
sparc_reg Sparc_map_register(unsigned int r)
{
	static unsigned int map[] = { 0,
		SPARC_REG_ICC, SPARC_REG_Y, SPARC_REG_F0, SPARC_REG_F2, SPARC_REG_F4,
		SPARC_REG_F6, SPARC_REG_F8, SPARC_REG_F10, SPARC_REG_F12, SPARC_REG_F14,
		SPARC_REG_F16, SPARC_REG_F18, SPARC_REG_F20, SPARC_REG_F22, SPARC_REG_F24,
		SPARC_REG_F26, SPARC_REG_F28, SPARC_REG_F30, SPARC_REG_F32, SPARC_REG_F34,
		SPARC_REG_F36, SPARC_REG_F38, SPARC_REG_F40, SPARC_REG_F42, SPARC_REG_F44,
		SPARC_REG_F46, SPARC_REG_F48, SPARC_REG_F50, SPARC_REG_F52, SPARC_REG_F54,
		SPARC_REG_F56, SPARC_REG_F58, SPARC_REG_F60, SPARC_REG_F62, SPARC_REG_F0,
		SPARC_REG_F1, SPARC_REG_F2, SPARC_REG_F3, SPARC_REG_F4, SPARC_REG_F5,
		SPARC_REG_F6, SPARC_REG_F7, SPARC_REG_F8, SPARC_REG_F9, SPARC_REG_F10,
		SPARC_REG_F11, SPARC_REG_F12, SPARC_REG_F13, SPARC_REG_F14, SPARC_REG_F15,
		SPARC_REG_F16, SPARC_REG_F17, SPARC_REG_F18, SPARC_REG_F19, SPARC_REG_F20,
		SPARC_REG_F21, SPARC_REG_F22, SPARC_REG_F23, SPARC_REG_F24, SPARC_REG_F25,
		SPARC_REG_F26, SPARC_REG_F27, SPARC_REG_F28, SPARC_REG_F29, SPARC_REG_F30,
		SPARC_REG_F31, SPARC_REG_FCC0, SPARC_REG_FCC1, SPARC_REG_FCC2, SPARC_REG_FCC3,
		SPARC_REG_G0, SPARC_REG_G1, SPARC_REG_G2, SPARC_REG_G3, SPARC_REG_G4,
		SPARC_REG_G5, SPARC_REG_G6, SPARC_REG_G7, SPARC_REG_I0, SPARC_REG_I1,
		SPARC_REG_I2, SPARC_REG_I3, SPARC_REG_I4, SPARC_REG_I5, SPARC_REG_FP,
		SPARC_REG_I7, SPARC_REG_L0, SPARC_REG_L1, SPARC_REG_L2, SPARC_REG_L3,
		SPARC_REG_L4, SPARC_REG_L5, SPARC_REG_L6, SPARC_REG_L7, SPARC_REG_O0,
		SPARC_REG_O1, SPARC_REG_O2, SPARC_REG_O3, SPARC_REG_O4, SPARC_REG_O5,
		SPARC_REG_SP, SPARC_REG_O7, SPARC_REG_F0, SPARC_REG_F4, SPARC_REG_F8,
		SPARC_REG_F12, SPARC_REG_F16, SPARC_REG_F20, SPARC_REG_F24, SPARC_REG_F28,
		SPARC_REG_F32, SPARC_REG_F36, SPARC_REG_F40, SPARC_REG_F44, SPARC_REG_F48,
		SPARC_REG_F52, SPARC_REG_F56, SPARC_REG_F60,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

// map instruction name to instruction ID (public)
sparc_reg Sparc_map_insn(const char *name)
{
	unsigned int i;

	// NOTE: skip first NULL name in insn_name_maps
	i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	return (i != -1)? i : SPARC_REG_INVALID;
}

// NOTE: put strings in the order of string length since
// we are going to compare with mnemonic to find out CC
static name_map alias_icc_maps[] = {
	{ SPARC_CC_ICC_LEU, "leu" },
	{ SPARC_CC_ICC_POS, "pos" },
	{ SPARC_CC_ICC_NEG, "neg" },
	{ SPARC_CC_ICC_NE, "ne" },
	{ SPARC_CC_ICC_LE, "le" },
	{ SPARC_CC_ICC_GE, "ge" },
	{ SPARC_CC_ICC_GU, "gu" },
	{ SPARC_CC_ICC_CC, "cc" },
	{ SPARC_CC_ICC_CS, "cs" },
	{ SPARC_CC_ICC_VC, "vc" },
	{ SPARC_CC_ICC_VS, "vs" },
	{ SPARC_CC_ICC_A, "a" },
	{ SPARC_CC_ICC_N, "n" },
	{ SPARC_CC_ICC_E, "e" },
	{ SPARC_CC_ICC_G, "g" },
	{ SPARC_CC_ICC_L, "l" },
};

static name_map alias_fcc_maps[] = {
	{ SPARC_CC_FCC_UGE, "uge" },
	{ SPARC_CC_FCC_ULE, "ule" },
	{ SPARC_CC_FCC_UG, "ug" },
	{ SPARC_CC_FCC_UL, "ul" },
	{ SPARC_CC_FCC_LG, "lg" },
	{ SPARC_CC_FCC_NE, "ne" },
	{ SPARC_CC_FCC_UE, "ue" },
	{ SPARC_CC_FCC_GE, "ge" },
	{ SPARC_CC_FCC_LE, "le" },
	{ SPARC_CC_FCC_A, "a" },
	{ SPARC_CC_FCC_N, "n" },
	{ SPARC_CC_FCC_U, "u" },
	{ SPARC_CC_FCC_G, "g" },
	{ SPARC_CC_FCC_L, "l" },
	{ SPARC_CC_FCC_E, "e" },
	{ SPARC_CC_FCC_O, "o" },
};

// map CC string to CC id
sparc_cc Sparc_map_ICC(const char *name)
{
	unsigned int i;

	i = name2id(alias_icc_maps, ARR_SIZE(alias_icc_maps), name);

	return (i != -1)? i : SPARC_CC_INVALID;
}

sparc_cc Sparc_map_FCC(const char *name)
{
	unsigned int i;

	i = name2id(alias_fcc_maps, ARR_SIZE(alias_fcc_maps), name);

	return (i != -1)? i : SPARC_CC_INVALID;
}

static name_map hint_maps[] = {
	{ SPARC_HINT_A, ",a" },
	{ SPARC_HINT_A | SPARC_HINT_PN, ",a,pn" },
	{ SPARC_HINT_PN, ",pn" },
};

sparc_hint Sparc_map_hint(const char *name)
{
	size_t i, l1, l2;

	l1 = strlen(name);
	for(i = 0; i < ARR_SIZE(hint_maps); i++) {
		l2 = strlen(hint_maps[i].name);
		if (l1 > l2) {
			// compare the last part of @name with this hint string
			if (!strcmp(hint_maps[i].name, name + (l1 - l2)))
				return hint_maps[i].id;
		}
	}

	return SPARC_HINT_INVALID;
}

#endif
