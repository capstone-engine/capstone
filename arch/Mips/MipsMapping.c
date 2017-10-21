/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_MIPS

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "MipsMapping.h"

#define GET_INSTRINFO_ENUM
#include "MipsGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ MIPS_REG_INVALID, NULL },

	//{ MIPS_REG_0, "0"},
	{ MIPS_REG_0, "zero"},
	{ MIPS_REG_1, "at"},
	//{ MIPS_REG_1, "1"},
	{ MIPS_REG_2, "v0"},
	//{ MIPS_REG_2, "2"},
	{ MIPS_REG_3, "v1"},
	//{ MIPS_REG_3, "3"},
	{ MIPS_REG_4, "a0"},
	//{ MIPS_REG_4, "4"},
	{ MIPS_REG_5, "a1"},
	//{ MIPS_REG_5, "5"},
	{ MIPS_REG_6, "a2"},
	//{ MIPS_REG_6, "6"},
	{ MIPS_REG_7, "a3"},
	//{ MIPS_REG_7, "7"},
	{ MIPS_REG_8, "t0"},
	//{ MIPS_REG_8, "8"},
	{ MIPS_REG_9, "t1"},
	//{ MIPS_REG_9, "9"},
	{ MIPS_REG_10, "t2"},
	//{ MIPS_REG_10, "10"},
	{ MIPS_REG_11, "t3"},
	//{ MIPS_REG_11, "11"},
	{ MIPS_REG_12, "t4"},
	//{ MIPS_REG_12, "12"},
	{ MIPS_REG_13, "t5"},
	//{ MIPS_REG_13, "13"},
	{ MIPS_REG_14, "t6"},
	//{ MIPS_REG_14, "14"},
	{ MIPS_REG_15, "t7"},
	//{ MIPS_REG_15, "15"},
	{ MIPS_REG_16, "s0"},
	//{ MIPS_REG_16, "16"},
	{ MIPS_REG_17, "s1"},
	//{ MIPS_REG_17, "17"},
	{ MIPS_REG_18, "s2"},
	//{ MIPS_REG_18, "18"},
	{ MIPS_REG_19, "s3"},
	//{ MIPS_REG_19, "19"},
	{ MIPS_REG_20, "s4"},
	//{ MIPS_REG_20, "20"},
	{ MIPS_REG_21, "s5"},
	//{ MIPS_REG_21, "21"},
	{ MIPS_REG_22, "s6"},
	//{ MIPS_REG_22, "22"},
	{ MIPS_REG_23, "s7"},
	//{ MIPS_REG_23, "23"},
	{ MIPS_REG_24, "t8"},
	//{ MIPS_REG_24, "24"},
	{ MIPS_REG_25, "t9"},
	//{ MIPS_REG_25, "25"},
	{ MIPS_REG_26, "k0"},
	//{ MIPS_REG_26, "26"},
	{ MIPS_REG_27, "k1"},
	//{ MIPS_REG_27, "27"},
	{ MIPS_REG_28, "gp"},
	//{ MIPS_REG_28, "28"},
	{ MIPS_REG_29, "sp"},
	//{ MIPS_REG_29, "29"},
	{ MIPS_REG_30, "fp"},
	//{ MIPS_REG_30, "30"},
	{ MIPS_REG_31, "ra"},
	//{ MIPS_REG_31, "31"},

	{ MIPS_REG_DSPCCOND, "dspccond"},
	{ MIPS_REG_DSPCARRY, "dspcarry"},
	{ MIPS_REG_DSPEFI, "dspefi"},
	{ MIPS_REG_DSPOUTFLAG, "dspoutflag"},
	{ MIPS_REG_DSPOUTFLAG16_19, "dspoutflag16_19"},
	{ MIPS_REG_DSPOUTFLAG20, "dspoutflag20"},
	{ MIPS_REG_DSPOUTFLAG21, "dspoutflag21"},
	{ MIPS_REG_DSPOUTFLAG22, "dspoutflag22"},
	{ MIPS_REG_DSPOUTFLAG23, "dspoutflag23"},
	{ MIPS_REG_DSPPOS, "dsppos"},
	{ MIPS_REG_DSPSCOUNT, "dspscount"},

	{ MIPS_REG_AC0, "ac0"},
	{ MIPS_REG_AC1, "ac1"},
	{ MIPS_REG_AC2, "ac2"},
	{ MIPS_REG_AC3, "ac3"},

	{ MIPS_REG_CC0, "cc0"},
	{ MIPS_REG_CC1, "cc1"},
	{ MIPS_REG_CC2, "cc2"},
	{ MIPS_REG_CC3, "cc3"},
	{ MIPS_REG_CC4, "cc4"},
	{ MIPS_REG_CC5, "cc5"},
	{ MIPS_REG_CC6, "cc6"},
	{ MIPS_REG_CC7, "cc7"},

	{ MIPS_REG_F0, "f0"},
	{ MIPS_REG_F1, "f1"},
	{ MIPS_REG_F2, "f2"},
	{ MIPS_REG_F3, "f3"},
	{ MIPS_REG_F4, "f4"},
	{ MIPS_REG_F5, "f5"},
	{ MIPS_REG_F6, "f6"},
	{ MIPS_REG_F7, "f7"},
	{ MIPS_REG_F8, "f8"},
	{ MIPS_REG_F9, "f9"},
	{ MIPS_REG_F10, "f10"},
	{ MIPS_REG_F11, "f11"},
	{ MIPS_REG_F12, "f12"},
	{ MIPS_REG_F13, "f13"},
	{ MIPS_REG_F14, "f14"},
	{ MIPS_REG_F15, "f15"},
	{ MIPS_REG_F16, "f16"},
	{ MIPS_REG_F17, "f17"},
	{ MIPS_REG_F18, "f18"},
	{ MIPS_REG_F19, "f19"},
	{ MIPS_REG_F20, "f20"},
	{ MIPS_REG_F21, "f21"},
	{ MIPS_REG_F22, "f22"},
	{ MIPS_REG_F23, "f23"},
	{ MIPS_REG_F24, "f24"},
	{ MIPS_REG_F25, "f25"},
	{ MIPS_REG_F26, "f26"},
	{ MIPS_REG_F27, "f27"},
	{ MIPS_REG_F28, "f28"},
	{ MIPS_REG_F29, "f29"},
	{ MIPS_REG_F30, "f30"},
	{ MIPS_REG_F31, "f31"},

	{ MIPS_REG_FCC0, "fcc0"},
	{ MIPS_REG_FCC1, "fcc1"},
	{ MIPS_REG_FCC2, "fcc2"},
	{ MIPS_REG_FCC3, "fcc3"},
	{ MIPS_REG_FCC4, "fcc4"},
	{ MIPS_REG_FCC5, "fcc5"},
	{ MIPS_REG_FCC6, "fcc6"},
	{ MIPS_REG_FCC7, "fcc7"},

	{ MIPS_REG_W0, "w0"},
	{ MIPS_REG_W1, "w1"},
	{ MIPS_REG_W2, "w2"},
	{ MIPS_REG_W3, "w3"},
	{ MIPS_REG_W4, "w4"},
	{ MIPS_REG_W5, "w5"},
	{ MIPS_REG_W6, "w6"},
	{ MIPS_REG_W7, "w7"},
	{ MIPS_REG_W8, "w8"},
	{ MIPS_REG_W9, "w9"},
	{ MIPS_REG_W10, "w10"},
	{ MIPS_REG_W11, "w11"},
	{ MIPS_REG_W12, "w12"},
	{ MIPS_REG_W13, "w13"},
	{ MIPS_REG_W14, "w14"},
	{ MIPS_REG_W15, "w15"},
	{ MIPS_REG_W16, "w16"},
	{ MIPS_REG_W17, "w17"},
	{ MIPS_REG_W18, "w18"},
	{ MIPS_REG_W19, "w19"},
	{ MIPS_REG_W20, "w20"},
	{ MIPS_REG_W21, "w21"},
	{ MIPS_REG_W22, "w22"},
	{ MIPS_REG_W23, "w23"},
	{ MIPS_REG_W24, "w24"},
	{ MIPS_REG_W25, "w25"},
	{ MIPS_REG_W26, "w26"},
	{ MIPS_REG_W27, "w27"},
	{ MIPS_REG_W28, "w28"},
	{ MIPS_REG_W29, "w29"},
	{ MIPS_REG_W30, "w30"},
	{ MIPS_REG_W31, "w31"},

	{ MIPS_REG_HI, "hi"},
	{ MIPS_REG_LO, "lo"},

	{ MIPS_REG_P0, "p0"},
	{ MIPS_REG_P1, "p1"},
	{ MIPS_REG_P2, "p2"},

	{ MIPS_REG_MPL0, "mpl0"},
	{ MIPS_REG_MPL1, "mpl1"},
	{ MIPS_REG_MPL2, "mpl2"},
};
#endif

const char *Mips_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= MIPS_REG_ENDING)
		return NULL;

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

static const insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
		Mips_ABSQ_S_PH, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ABSQ_S_QB, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ABSQ_S_W, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDIUPC, MIPS_INS_ADDIUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQH_PH, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQH_R_PH, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQH_R_W, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQH_W, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQ_PH, MIPS_INS_ADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQ_S_PH, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDQ_S_W, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDSC, MIPS_INS_ADDSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCARRY, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_A_B, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_A_D, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_A_H, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_A_W, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_S_B, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_S_D, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_S_H, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_S_W, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_U_B, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_U_D, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_U_H, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDS_U_W, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDUH_QB, MIPS_INS_ADDUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDUH_R_QB, MIPS_INS_ADDUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDU_PH, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDU_QB, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDU_S_PH, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDU_S_QB, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDVI_B, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDVI_D, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDVI_H, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDVI_W, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDV_B, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDV_D, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDV_H, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDV_W, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDWC, MIPS_INS_ADDWC,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPCARRY, 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD_A_B, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD_A_D, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD_A_H, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD_A_W, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ADD_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDi, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDi_MM, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDiu, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDiu_MM, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDu, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ADDu_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ALIGN, MIPS_INS_ALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_ALUIPC, MIPS_INS_ALUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_AND, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_AND64, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ANDI_B, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AND_MM, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_AND_V, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ANDi, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ANDi64, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ANDi_MM, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_APPEND, MIPS_INS_APPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_S_B, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_S_D, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_S_H, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_S_W, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_U_B, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_U_D, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_U_H, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ASUB_U_W, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AUI, MIPS_INS_AUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_AUIPC, MIPS_INS_AUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_S_B, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_S_D, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_S_H, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_S_W, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_U_B, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_U_D, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_U_H, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVER_U_W, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_S_B, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_S_D, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_S_H, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_S_W, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_U_B, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_U_D, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_U_H, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AVE_U_W, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuRxImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuRxPcImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuRxRxImm16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuRxRxImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuRxRyOffMemX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuSpImm16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_SP, 0 }, { MIPS_REG_SP, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AddiuSpImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_SP, 0 }, { MIPS_REG_SP, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AdduRxRyRz16, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_AndRxRxRy16, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_BADDu, MIPS_INS_BADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BAL, MIPS_INS_BAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BALC, MIPS_INS_BALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BALIGN, MIPS_INS_BALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_BC, MIPS_INS_BC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC0F, MIPS_INS_BC0F,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC0FL, MIPS_INS_BC0FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC0T, MIPS_INS_BC0T,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC0TL, MIPS_INS_BC0TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1EQZ, MIPS_INS_BC1EQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1F, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1FL, MIPS_INS_BC1FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1F_MM, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1NEZ, MIPS_INS_BC1NEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1T, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1TL, MIPS_INS_BC1TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC1T_MM, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2EQZ, MIPS_INS_BC2EQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2F, MIPS_INS_BC2F,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2FL, MIPS_INS_BC2FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2NEZ, MIPS_INS_BC2NEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2T, MIPS_INS_BC2T,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC2TL, MIPS_INS_BC2TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC3F, MIPS_INS_BC3F,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC3FL, MIPS_INS_BC3FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC3T, MIPS_INS_BC3T,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BC3TL, MIPS_INS_BC3TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BCLRI_B, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLRI_D, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLRI_H, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLRI_W, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLR_B, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLR_D, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLR_H, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BCLR_W, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BEQ, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQ64, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQC, MIPS_INS_BEQC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQL, MIPS_INS_BEQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQZALC, MIPS_INS_BEQZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQZC, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQZC_MM, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BEQ_MM, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEC, MIPS_INS_BGEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEUC, MIPS_INS_BGEUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZ, MIPS_INS_BGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZ64, MIPS_INS_BGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZAL, MIPS_INS_BGEZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_BGEZALC, MIPS_INS_BGEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZALL, MIPS_INS_BGEZALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZALS_MM, MIPS_INS_BGEZALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BGEZAL_MM, MIPS_INS_BGEZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BGEZC, MIPS_INS_BGEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZL, MIPS_INS_BGEZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGEZ_MM, MIPS_INS_BGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZ, MIPS_INS_BGTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZ64, MIPS_INS_BGTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZALC, MIPS_INS_BGTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZC, MIPS_INS_BGTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZL, MIPS_INS_BGTZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BGTZ_MM, MIPS_INS_BGTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BINSLI_B, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSLI_D, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSLI_H, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSLI_W, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSL_B, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSL_D, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSL_H, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSL_W, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSRI_B, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSRI_D, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSRI_H, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSRI_W, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSR_B, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSR_D, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSR_H, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BINSR_W, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BITREV, MIPS_INS_BITREV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_BITSWAP, MIPS_INS_BITSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_BLEZ, MIPS_INS_BLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLEZ64, MIPS_INS_BLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLEZALC, MIPS_INS_BLEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLEZC, MIPS_INS_BLEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLEZL, MIPS_INS_BLEZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLEZ_MM, MIPS_INS_BLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTC, MIPS_INS_BLTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTUC, MIPS_INS_BLTUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZ, MIPS_INS_BLTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZ64, MIPS_INS_BLTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZAL, MIPS_INS_BLTZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_BLTZALC, MIPS_INS_BLTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZALL, MIPS_INS_BLTZALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZALS_MM, MIPS_INS_BLTZALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BLTZAL_MM, MIPS_INS_BLTZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BLTZC, MIPS_INS_BLTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZL, MIPS_INS_BLTZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BLTZ_MM, MIPS_INS_BLTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BMNZI_B, MIPS_INS_BMNZI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BMNZ_V, MIPS_INS_BMNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BMZI_B, MIPS_INS_BMZI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BMZ_V, MIPS_INS_BMZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNE, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BNE64, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BNEC, MIPS_INS_BNEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BNEGI_B, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEGI_D, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEGI_H, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEGI_W, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEG_B, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEG_D, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEG_H, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEG_W, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BNEL, MIPS_INS_BNEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_BNEZALC, MIPS_INS_BNEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BNEZC, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BNEZC_MM, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BNE_MM, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
		Mips_BNVC, MIPS_INS_BNVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BNZ_B, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BNZ_D, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BNZ_H, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BNZ_V, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BNZ_W, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BOVC, MIPS_INS_BOVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
		Mips_BPOSGE32, MIPS_INS_BPOSGE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 1, 0
#endif
	},
	{
		Mips_BREAK, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_BREAK_MM, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_BSELI_B, MIPS_INS_BSELI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSEL_V, MIPS_INS_BSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSETI_B, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSETI_D, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSETI_H, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSETI_W, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSET_B, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSET_D, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSET_H, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BSET_W, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_BZ_B, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BZ_D, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BZ_H, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BZ_V, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BZ_W, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
		Mips_BeqzRxImm16, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BeqzRxImmX16, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_Bimm16, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BimmX16, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BnezRxImm16, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BnezRxImmX16, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_Break16, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_Bteqz16, MIPS_INS_BTEQZ,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_T8, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BteqzX16, MIPS_INS_BTEQZ,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_T8, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_Btnez16, MIPS_INS_BTNEZ,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_T8, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_BtnezX16, MIPS_INS_BTNEZ,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_T8, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
		Mips_CACHE, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CACHE_R6, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_L_D64, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_L_S, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_W_D32, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_W_D64, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_W_MM, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_W_S, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_CEIL_W_S_MM, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQI_B, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQI_D, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQI_H, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQI_W, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQ_B, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQ_D, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQ_H, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CEQ_W, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CFC1, MIPS_INS_CFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_CFC1_MM, MIPS_INS_CFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CFCMSA, MIPS_INS_CFCMSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CINS, MIPS_INS_CINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CINS32, MIPS_INS_CINS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CLASS_D, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CLASS_S, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_S_B, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_S_D, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_S_H, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_S_W, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_U_B, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_U_D, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_U_H, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLEI_U_W, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_S_B, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_S_D, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_S_H, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_S_W, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_U_B, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_U_D, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_U_H, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLE_U_W, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLO, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CLO_MM, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CLO_R6, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_S_B, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_S_D, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_S_H, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_S_W, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_U_B, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_U_D, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_U_H, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLTI_U_W, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_S_B, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_S_D, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_S_H, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_S_W, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_U_B, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_U_D, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_U_H, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLT_U_W, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CLZ, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CLZ_MM, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CLZ_R6, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGDU_EQ_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGDU_LE_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGDU_LT_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGU_EQ_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGU_LE_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPGU_LT_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPU_EQ_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPU_LE_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMPU_LT_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_EQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_EQ_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_EQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_F_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_F_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LE_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LT_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPCCOND, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_LT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SAF_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SAF_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SLE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SLE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SLT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SLT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SUEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SUEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SULE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SULE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SULT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SULT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SUN_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_SUN_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_UEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_UEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_ULE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_ULE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_ULT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_ULT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_UN_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CMP_UN_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_S_B, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_S_D, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_S_H, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_S_W, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_U_B, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_U_D, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_U_H, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_COPY_U_W, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CTC1, MIPS_INS_CTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_CTC1_MM, MIPS_INS_CTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CTCMSA, MIPS_INS_CTCMSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D32_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D32_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D32_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D64_L, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D64_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D64_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_D_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_L_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_L_D64_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_L_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_L_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_D32, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_D32_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_L, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_S_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_W_D32, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_W_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_W_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_CVT_W_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_C_EQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_EQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_EQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_F_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_F_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_F_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_LT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGL_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGL_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGL_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_NGT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_OLT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SF_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SF_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_SF_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_ULT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UN_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UN_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_C_UN_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_CmpRxRy16, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_CmpiRxImm16, MIPS_INS_CMPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_CmpiRxImmX16, MIPS_INS_CMPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_DADD, MIPS_INS_DADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DADDi, MIPS_INS_DADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DADDiu, MIPS_INS_DADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DADDu, MIPS_INS_DADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DAHI, MIPS_INS_DAHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DALIGN, MIPS_INS_DALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DATI, MIPS_INS_DATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DAUI, MIPS_INS_DAUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DBITSWAP, MIPS_INS_DBITSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DCLO, MIPS_INS_DCLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DCLO_R6, MIPS_INS_DCLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DCLZ, MIPS_INS_DCLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DCLZ_R6, MIPS_INS_DCLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DDIV, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DDIVU, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DERET, MIPS_INS_DERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 0
#endif
	},
	{
		Mips_DERET_MM, MIPS_INS_DERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_DEXT, MIPS_INS_DEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DEXTM, MIPS_INS_DEXTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DEXTU, MIPS_INS_DEXTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DI, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DINS, MIPS_INS_DINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DINSM, MIPS_INS_DINSM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DINSU, MIPS_INS_DINSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DIVU, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_S_B, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_S_D, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_S_H, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_S_W, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_U_B, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_U_D, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_U_H, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DIV_U_W, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DI_MM, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_DLSA, MIPS_INS_DLSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_DLSA_R6, MIPS_INS_DLSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMFC0, MIPS_INS_DMFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_DMFC1, MIPS_INS_DMFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DMFC2, MIPS_INS_DMFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_DMOD, MIPS_INS_DMOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMODU, MIPS_INS_DMODU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMTC0, MIPS_INS_DMTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_DMTC1, MIPS_INS_DMTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DMTC2, MIPS_INS_DMTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_DMUH, MIPS_INS_DMUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMUHU, MIPS_INS_DMUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMUL, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_DMULT, MIPS_INS_DMULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMULTu, MIPS_INS_DMULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMULU, MIPS_INS_DMULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DMUL_R6, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_S_D, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_S_H, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_S_W, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_U_D, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_U_H, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DOTP_U_W, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_S_D, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_S_H, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_S_W, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_U_D, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_U_H, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPADD_U_W, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAQX_SA_W_PH, MIPS_INS_DPAQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAQX_S_W_PH, MIPS_INS_DPAQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAQ_SA_L_W, MIPS_INS_DPAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAQ_S_W_PH, MIPS_INS_DPAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAU_H_QBL, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAU_H_QBR, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPAX_W_PH, MIPS_INS_DPAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPA_W_PH, MIPS_INS_DPA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPOP, MIPS_INS_DPOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSQX_SA_W_PH, MIPS_INS_DPSQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSQX_S_W_PH, MIPS_INS_DPSQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSQ_SA_L_W, MIPS_INS_DPSQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSQ_S_W_PH, MIPS_INS_DPSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_S_D, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_S_H, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_S_W, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_U_D, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_U_H, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSUB_U_W, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSU_H_QBL, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSU_H_QBR, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_DPSX_W_PH, MIPS_INS_DPSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DPS_W_PH, MIPS_INS_DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_DROTR, MIPS_INS_DROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DROTR32, MIPS_INS_DROTR32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DROTRV, MIPS_INS_DROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DSBH, MIPS_INS_DSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DSDIV, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DSHD, MIPS_INS_DSHD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, 0 }, 0, 0
#endif
	},
	{
		Mips_DSLL, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSLL32, MIPS_INS_DSLL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSLL64_32, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_DSLLV, MIPS_INS_DSLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRA, MIPS_INS_DSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRA32, MIPS_INS_DSRA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRAV, MIPS_INS_DSRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRL, MIPS_INS_DSRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRL32, MIPS_INS_DSRL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSRLV, MIPS_INS_DSRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSUB, MIPS_INS_DSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DSUBu, MIPS_INS_DSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_DUDIV, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_DivRxRy16, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_DivuRxRy16, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_EHB, MIPS_INS_EHB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_EI, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_EI_MM, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ERET, MIPS_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, 0 }, 0, 0
#endif
	},
	{
		Mips_ERET_MM, MIPS_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_EXT, MIPS_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTP, MIPS_INS_EXTP,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPPOS, 0 }, { MIPS_REG_DSPEFI, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTPDP, MIPS_INS_EXTPDP,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPPOS, 0 }, { MIPS_REG_DSPPOS, MIPS_REG_DSPEFI, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTPDPV, MIPS_INS_EXTPDPV,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPPOS, 0 }, { MIPS_REG_DSPPOS, MIPS_REG_DSPEFI, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTPV, MIPS_INS_EXTPV,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPPOS, 0 }, { MIPS_REG_DSPEFI, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTRV_RS_W, MIPS_INS_EXTRV_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTRV_R_W, MIPS_INS_EXTRV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTRV_S_H, MIPS_INS_EXTRV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTRV_W, MIPS_INS_EXTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTR_RS_W, MIPS_INS_EXTR_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTR_R_W, MIPS_INS_EXTR_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTR_S_H, MIPS_INS_EXTR_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTR_W, MIPS_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG23, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTS, MIPS_INS_EXTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_EXTS32, MIPS_INS_EXTS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_EXT_MM, MIPS_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FABS_D32, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FABS_D64, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FABS_MM, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FABS_S, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FABS_S_MM, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_D, MIPS_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_D32, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_D64, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_S, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_S_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FADD_W, MIPS_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCAF_D, MIPS_INS_FCAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCAF_W, MIPS_INS_FCAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCEQ_D, MIPS_INS_FCEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCEQ_W, MIPS_INS_FCEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLASS_D, MIPS_INS_FCLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLASS_W, MIPS_INS_FCLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLE_D, MIPS_INS_FCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLE_W, MIPS_INS_FCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLT_D, MIPS_INS_FCLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCLT_W, MIPS_INS_FCLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCMP_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_FCC0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FCMP_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_FCC0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FCMP_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_FCC0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FCMP_S32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_FCC0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_FCMP_S32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_FCC0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FCNE_D, MIPS_INS_FCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCNE_W, MIPS_INS_FCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCOR_D, MIPS_INS_FCOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCOR_W, MIPS_INS_FCOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUEQ_D, MIPS_INS_FCUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUEQ_W, MIPS_INS_FCUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCULE_D, MIPS_INS_FCULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCULE_W, MIPS_INS_FCULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCULT_D, MIPS_INS_FCULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCULT_W, MIPS_INS_FCULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUNE_D, MIPS_INS_FCUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUNE_W, MIPS_INS_FCUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUN_D, MIPS_INS_FCUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FCUN_W, MIPS_INS_FCUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_D, MIPS_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_D32, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_D64, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_S, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_S_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FDIV_W, MIPS_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXDO_H, MIPS_INS_FEXDO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXDO_W, MIPS_INS_FEXDO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXP2_D, MIPS_INS_FEXP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXP2_W, MIPS_INS_FEXP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXUPL_D, MIPS_INS_FEXUPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXUPL_W, MIPS_INS_FEXUPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXUPR_D, MIPS_INS_FEXUPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FEXUPR_W, MIPS_INS_FEXUPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFINT_S_D, MIPS_INS_FFINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFINT_S_W, MIPS_INS_FFINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFINT_U_D, MIPS_INS_FFINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFINT_U_W, MIPS_INS_FFINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFQL_D, MIPS_INS_FFQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFQL_W, MIPS_INS_FFQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFQR_D, MIPS_INS_FFQR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FFQR_W, MIPS_INS_FFQR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FILL_B, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FILL_D, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_FILL_H, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FILL_W, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOG2_D, MIPS_INS_FLOG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOG2_W, MIPS_INS_FLOG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_L_D64, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_L_S, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_W_D32, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_W_D64, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_W_MM, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_W_S, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_FLOOR_W_S_MM, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FMADD_D, MIPS_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMADD_W, MIPS_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMAX_A_D, MIPS_INS_FMAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMAX_A_W, MIPS_INS_FMAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMAX_D, MIPS_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMAX_W, MIPS_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMIN_A_D, MIPS_INS_FMIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMIN_A_W, MIPS_INS_FMIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMIN_D, MIPS_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMIN_W, MIPS_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMOV_D32, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FMOV_D32_MM, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FMOV_D64, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FMOV_S, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FMOV_S_MM, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FMSUB_D, MIPS_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMSUB_W, MIPS_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_D, MIPS_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_D32, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_D64, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_S, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_S_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FMUL_W, MIPS_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FNEG_D32, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FNEG_D64, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FNEG_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FNEG_S, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FNEG_S_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FRCP_D, MIPS_INS_FRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FRCP_W, MIPS_INS_FRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FRINT_D, MIPS_INS_FRINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FRINT_W, MIPS_INS_FRINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FRSQRT_D, MIPS_INS_FRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FRSQRT_W, MIPS_INS_FRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSAF_D, MIPS_INS_FSAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSAF_W, MIPS_INS_FSAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSEQ_D, MIPS_INS_FSEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSEQ_W, MIPS_INS_FSEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSLE_D, MIPS_INS_FSLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSLE_W, MIPS_INS_FSLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSLT_D, MIPS_INS_FSLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSLT_W, MIPS_INS_FSLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSNE_D, MIPS_INS_FSNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSNE_W, MIPS_INS_FSNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSOR_D, MIPS_INS_FSOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSOR_W, MIPS_INS_FSOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_D, MIPS_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_D32, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_D64, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_MM, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_S, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_S_MM, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FSQRT_W, MIPS_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_D, MIPS_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_D32, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_D64, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_S, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_S_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUB_W, MIPS_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUEQ_D, MIPS_INS_FSUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUEQ_W, MIPS_INS_FSUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSULE_D, MIPS_INS_FSULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSULE_W, MIPS_INS_FSULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSULT_D, MIPS_INS_FSULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSULT_W, MIPS_INS_FSULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUNE_D, MIPS_INS_FSUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUNE_W, MIPS_INS_FSUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUN_D, MIPS_INS_FSUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FSUN_W, MIPS_INS_FSUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTINT_S_D, MIPS_INS_FTINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTINT_S_W, MIPS_INS_FTINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTINT_U_D, MIPS_INS_FTINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTINT_U_W, MIPS_INS_FTINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTQ_H, MIPS_INS_FTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTQ_W, MIPS_INS_FTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTRUNC_S_D, MIPS_INS_FTRUNC_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTRUNC_S_W, MIPS_INS_FTRUNC_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTRUNC_U_D, MIPS_INS_FTRUNC_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_FTRUNC_U_W, MIPS_INS_FTRUNC_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_S_D, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_S_H, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_S_W, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_U_D, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_U_H, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HADD_U_W, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_S_D, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_S_H, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_S_W, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_U_D, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_U_H, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_HSUB_U_W, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVEV_B, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVEV_D, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVEV_H, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVEV_W, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVL_B, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVL_D, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVL_H, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVL_W, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVOD_B, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVOD_D, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVOD_H, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVOD_W, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVR_B, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVR_D, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVR_H, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ILVR_W, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INS, MIPS_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_INSERT_B, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSERT_D, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_INSERT_H, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSERT_W, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSV, MIPS_INS_INSV,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPPOS, MIPS_REG_DSPSCOUNT, 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_INSVE_B, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSVE_D, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSVE_H, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INSVE_W, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_INS_MM, MIPS_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_J, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, 0 }, 1, 0
#endif
	},
	{
		Mips_JAL, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_JALR, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JALR16_MM, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JALR64, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_JALRS_MM, MIPS_INS_JALRS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JALR_HB, MIPS_INS_JALR_HB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 1
#endif
	},
	{
		Mips_JALR_MM, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JALS_MM, MIPS_INS_JALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JALX, MIPS_INS_JALX,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_JAL_MM, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_JIALC, MIPS_INS_JIALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_JIC, MIPS_INS_JIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_JR, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 1, 1
#endif
	},
	{
		Mips_JR64, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 1, 1
#endif
	},
	{
		Mips_JRADDIUSP, MIPS_INS_JRADDIUSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 1
#endif
	},
	{
		Mips_JR_HB, MIPS_INS_JR_HB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 1
#endif
	},
	{
		Mips_JR_HB_R6, MIPS_INS_JR_HB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
		Mips_JR_MM, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 1, 1
#endif
	},
	{
		Mips_J_MM, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_AT, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_Jal16, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_JrRa16, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
		Mips_JrcRa16, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
		Mips_JrcRx16, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
		Mips_JumpLinkReg16, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_RA, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LB, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LB64, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LBUX, MIPS_INS_LBUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_LB_MM, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LBu, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LBu64, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LBu_MM, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LD, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC1, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC164, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC1_MM, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC2, MIPS_INS_LDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC2_R6, MIPS_INS_LDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LDC3, MIPS_INS_LDC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_LDI_B, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LDI_D, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LDI_H, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LDI_W, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LDL, MIPS_INS_LDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LDPC, MIPS_INS_LDPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LDR, MIPS_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LDXC1, MIPS_INS_LDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_LDXC164, MIPS_INS_LDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LD_B, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LD_D, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LD_H, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LD_W, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LEA_ADDiu, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LEA_ADDiu64, MIPS_INS_DADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LEA_ADDiu_MM, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LH, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LH64, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LHX, MIPS_INS_LHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_LH_MM, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LHu, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LHu64, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LHu_MM, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LL, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LLD, MIPS_INS_LLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LLD_R6, MIPS_INS_LLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LL_MM, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LL_R6, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LSA, MIPS_INS_LSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_LSA_R6, MIPS_INS_LSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LUXC1, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_LUXC164, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LUXC1_MM, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LUi, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LUi64, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LUi_MM, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LW, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LW64, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LWC1, MIPS_INS_LWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LWC1_MM, MIPS_INS_LWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWC2, MIPS_INS_LWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LWC2_R6, MIPS_INS_LWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LWC3, MIPS_INS_LWC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LWL, MIPS_INS_LWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWL64, MIPS_INS_LWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LWL_MM, MIPS_INS_LWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWPC, MIPS_INS_LWPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LWR, MIPS_INS_LWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWR64, MIPS_INS_LWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_LWR_MM, MIPS_INS_LWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWUPC, MIPS_INS_LWUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_LWU_MM, MIPS_INS_LWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWX, MIPS_INS_LWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_LWXC1, MIPS_INS_LWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_LWXC1_MM, MIPS_INS_LWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LW_MM, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_LWu, MIPS_INS_LWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_LbRxRyOffMemX16, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LbuRxRyOffMemX16, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LhRxRyOffMemX16, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LhuRxRyOffMemX16, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LiRxImm16, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LiRxImmX16, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LwRxPcTcp16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LwRxPcTcpX16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LwRxRyOffMemX16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_LwRxSpImmX16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_SP, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDF_D, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDF_S, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDR_Q_H, MIPS_INS_MADDR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDR_Q_W, MIPS_INS_MADDR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDU, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDU_DSP, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDU_MM, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDV_B, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDV_D, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDV_H, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADDV_W, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_D32, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_D32_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_D64, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_DSP, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_Q_H, MIPS_INS_MADD_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_Q_W, MIPS_INS_MADD_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_S, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MADD_S_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MAQ_SA_W_PHL, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MAQ_SA_W_PHR, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MAQ_S_W_PHL, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MAQ_S_W_PHR, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXA_D, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXA_S, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_S_B, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_S_D, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_S_H, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_S_W, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_U_B, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_U_D, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_U_H, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAXI_U_W, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_A_B, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_A_D, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_A_H, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_A_W, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_D, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_S, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_S_B, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_S_D, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_S_H, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_S_W, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_U_B, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_U_D, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_U_H, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MAX_U_W, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MFC0, MIPS_INS_MFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 0
#endif
	},
	{
		Mips_MFC1, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_MFC1_MM, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFC2, MIPS_INS_MFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHC1_D32, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHC1_D64, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHC1_MM, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHI, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHI16_MM, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHI64, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHI_DSP, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MFHI_MM, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFLO, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFLO16_MM, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MFLO64, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MFLO_DSP, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MFLO_MM, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_AC0, 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MINA_D, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MINA_S, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_S_B, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_S_D, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_S_H, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_S_W, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_U_B, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_U_D, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_U_H, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MINI_U_W, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_A_B, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_A_D, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_A_H, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_A_W, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_D, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_S, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_S_B, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_S_D, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_S_H, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_S_W, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_U_B, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_U_D, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_U_H, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MIN_U_W, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD, MIPS_INS_MOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MODSUB, MIPS_INS_MODSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MODU, MIPS_INS_MODU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_S_B, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_S_D, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_S_H, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_S_W, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_U_B, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_U_D, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_U_H, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOD_U_W, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVE16_MM, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVE_V, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_D32, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_D32_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_D64, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_I, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_I64, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_I_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_S, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVF_S_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I64_D64, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I64_I, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I64_I64, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I64_S, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_D32, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_D32_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_D64, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_I, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_I64, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_S, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVN_I_S_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_D32, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_D32_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_D64, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_I, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_I64, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_I_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_S, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVT_S_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I64_D64, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I64_I, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I64_I64, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I64_S, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_D32, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_D32_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_D64, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_I, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_I64, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_S, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MOVZ_I_S_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBF_D, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBF_S, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBR_Q_H, MIPS_INS_MSUBR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBR_Q_W, MIPS_INS_MSUBR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBU, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBU_DSP, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBU_MM, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBV_B, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBV_D, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBV_H, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUBV_W, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_D32, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_D32_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_D64, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_DSP, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_Q_H, MIPS_INS_MSUB_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_Q_W, MIPS_INS_MSUB_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_S, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MSUB_S_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTC0, MIPS_INS_MTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 0
#endif
	},
	{
		Mips_MTC1, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_MTC1_MM, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTC2, MIPS_INS_MTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHC1_D32, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHC1_D64, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHC1_MM, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHI, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHI64, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHI_DSP, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHI_MM, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTHLIP, MIPS_INS_MTHLIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPPOS, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MTLO, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MTLO64, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MTLO_DSP, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MTLO_MM, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTM0, MIPS_INS_MTM0,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_MPL0, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTM1, MIPS_INS_MTM1,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_MPL1, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTM2, MIPS_INS_MTM2,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_MPL2, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTP0, MIPS_INS_MTP0,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_P0, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTP1, MIPS_INS_MTP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_P1, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MTP2, MIPS_INS_MTP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MUH, MIPS_INS_MUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MUHU, MIPS_INS_MUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MULEQ_S_W_PHL, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULEQ_S_W_PHR, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULEU_S_PH_QBL, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULEU_S_PH_QBR, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULQ_RS_PH, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULQ_RS_W, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_MULQ_S_PH, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_MULQ_S_W, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_MULR_Q_H, MIPS_INS_MULR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MULR_Q_W, MIPS_INS_MULR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MULSAQ_S_W_PH, MIPS_INS_MULSAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG16_19, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULSA_W_PH, MIPS_INS_MULSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_MULT, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MULTU_DSP, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULT_DSP, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_MULT_MM, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MULTu, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MULTu_MM, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MULU, MIPS_INS_MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MULV_B, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MULV_D, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MULV_H, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MULV_W, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_PH, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_Q_H, MIPS_INS_MUL_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_Q_W, MIPS_INS_MUL_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_R6, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_MUL_S_PH, MIPS_INS_MUL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG21, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_Mfhi16, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_HI0, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_Mflo16, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_LO0, 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_Move32R16, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_MoveR3216, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_NLOC_B, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLOC_D, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLOC_H, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLOC_W, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLZC_B, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLZC_D, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLZC_H, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NLZC_W, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NMADD_D32, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMADD_D32_MM, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_NMADD_D64, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMADD_S, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMADD_S_MM, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_NMSUB_D32, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMSUB_D32_MM, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_NMSUB_D64, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMSUB_S, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NONANSFPMATH, 0 }, 0, 0
#endif
	},
	{
		Mips_NMSUB_S_MM, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_NOR, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_NOR64, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_NORI_B, MIPS_INS_NORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NOR_MM, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_NOR_V, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_NegRxRy16, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_NotRxRy16, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_OR, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_OR64, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ORI_B, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_OR_MM, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_OR_V, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ORi, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ORi64, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ORi_MM, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_OrRxRxRy16, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_PACKRL_PH, MIPS_INS_PACKRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PAUSE, MIPS_INS_PAUSE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKEV_B, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKEV_D, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKEV_H, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKEV_W, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKOD_B, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKOD_D, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKOD_H, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCKOD_W, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCNT_B, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCNT_D, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCNT_H, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PCNT_W, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_PICK_PH, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPCCOND, 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PICK_QB, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ MIPS_REG_DSPCCOND, 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_POP, MIPS_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQU_PH_QBL, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQU_PH_QBLA, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQU_PH_QBR, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQU_PH_QBRA, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQ_W_PHL, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEQ_W_PHR, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEU_PH_QBL, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEU_PH_QBLA, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEU_PH_QBR, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECEU_PH_QBRA, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECRQU_S_QB_PH, MIPS_INS_PRECRQU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECRQ_PH_W, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECRQ_QB_PH, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECRQ_RS_PH_W, MIPS_INS_PRECRQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECR_QB_PH, MIPS_INS_PRECR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECR_SRA_PH_W, MIPS_INS_PRECR_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_PRECR_SRA_R_PH_W, MIPS_INS_PRECR_SRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_PREF, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_PREF_R6, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_PREPEND, MIPS_INS_PREPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_RADDU_W_QB, MIPS_INS_RADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_RDDSP, MIPS_INS_RDDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_RDHWR, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_RDHWR64, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_REPLV_PH, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_REPLV_QB, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_REPL_PH, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_REPL_QB, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_RINT_D, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_RINT_S, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_ROTR, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_ROTRV, MIPS_INS_ROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_ROTRV_MM, MIPS_INS_ROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ROTR_MM, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_L_D64, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_L_S, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_W_D32, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_W_D64, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_W_MM, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_W_S, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_ROUND_W_S_MM, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_S_B, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_S_D, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_S_H, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_S_W, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_U_B, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_U_D, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_U_H, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SAT_U_W, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SB, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SB64, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SB_MM, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SC, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SCD, MIPS_INS_SCD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SCD_R6, MIPS_INS_SCD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SC_MM, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SC_R6, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SD, MIPS_INS_SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
		Mips_SDBBP, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDBBP_R6, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC1, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC164, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC1_MM, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC2, MIPS_INS_SDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC2_R6, MIPS_INS_SDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDC3, MIPS_INS_SDC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_SDIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDIV_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SDL, MIPS_INS_SDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDR, MIPS_INS_SDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SDXC1, MIPS_INS_SDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_SDXC164, MIPS_INS_SDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SEB, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_SEB64, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_SEB_MM, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SEH, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_SEH64, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_SEH_MM, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SELEQZ, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELEQZ64, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELEQZ_D, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELEQZ_S, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELNEZ, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELNEZ64, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELNEZ_D, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SELNEZ_S, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SEL_D, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SEL_S, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SEQ, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SEQi, MIPS_INS_SEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SH, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SH64, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SHF_B, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SHF_H, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SHF_W, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SHILO, MIPS_INS_SHILO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHILOV, MIPS_INS_SHILOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLLV_PH, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLLV_QB, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLLV_S_PH, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLLV_S_W, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLL_PH, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLL_QB, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLL_S_PH, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHLL_S_W, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG22, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRAV_PH, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRAV_QB, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRAV_R_PH, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRAV_R_QB, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRAV_R_W, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRA_PH, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRA_QB, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRA_R_PH, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRA_R_QB, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRA_R_W, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRLV_PH, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRLV_QB, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRL_PH, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SHRL_QB, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SH_MM, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLDI_B, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLDI_D, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLDI_H, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLDI_W, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLD_B, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLD_D, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLD_H, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLD_W, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL64_32, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL64_64, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLI_B, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLI_D, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLI_H, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLI_W, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLV, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLLV_MM, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL_B, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL_D, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL_H, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLL_W, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SLT, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLT64, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLT_MM, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTi, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTi64, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTi_MM, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTiu, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTiu64, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTiu_MM, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTu, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTu64, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SLTu_MM, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SNE, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SNEi, MIPS_INS_SNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLATI_B, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLATI_D, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLATI_H, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLATI_W, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLAT_B, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLAT_D, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLAT_H, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SPLAT_W, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAI_B, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAI_D, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAI_H, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAI_W, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRARI_B, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRARI_D, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRARI_H, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRARI_W, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAR_B, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAR_D, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAR_H, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAR_W, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAV, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SRAV_MM, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA_B, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA_D, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA_H, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SRA_W, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLI_B, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLI_D, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLI_H, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLI_W, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLRI_B, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLRI_D, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLRI_H, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLRI_W, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLR_B, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLR_D, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLR_H, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLR_W, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLV, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SRLV_MM, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL_B, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL_D, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL_H, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SRL_W, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SSNOP, MIPS_INS_SSNOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_ST_B, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ST_D, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ST_H, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_ST_W, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUB, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQH_PH, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQH_R_PH, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQH_R_W, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQH_W, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQ_PH, MIPS_INS_SUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQ_S_PH, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBQ_S_W, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUS_U_B, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUS_U_D, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUS_U_H, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUS_U_W, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUU_S_B, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUU_S_D, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUU_S_H, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBSUU_S_W, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_S_B, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_S_D, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_S_H, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_S_W, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_U_B, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_U_D, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_U_H, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBS_U_W, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBUH_QB, MIPS_INS_SUBUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBUH_R_QB, MIPS_INS_SUBUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBU_PH, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBU_QB, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBU_S_PH, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBU_S_QB, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_DSPOUTFLAG20, 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBVI_B, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBVI_D, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBVI_H, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBVI_W, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBV_B, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBV_D, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBV_H, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBV_W, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_SUB_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBu, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SUBu_MM, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SUXC1, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_SUXC164, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SUXC1_MM, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SW, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SW64, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SWC1, MIPS_INS_SWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SWC1_MM, MIPS_INS_SWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SWC2, MIPS_INS_SWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SWC2_R6, MIPS_INS_SWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
		Mips_SWC3, MIPS_INS_SWC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SWL, MIPS_INS_SWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SWL64, MIPS_INS_SWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SWL_MM, MIPS_INS_SWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SWR, MIPS_INS_SWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SWR64, MIPS_INS_SWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SWR_MM, MIPS_INS_SWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SWXC1, MIPS_INS_SWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTNACL, 0 }, 0, 0
#endif
	},
	{
		Mips_SWXC1_MM, MIPS_INS_SWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SW_MM, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SYNC, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 0
#endif
	},
	{
		Mips_SYNC_MM, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SYSCALL, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_SYSCALL_MM, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_SbRxRyOffMemX16, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SebRx16, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SehRx16, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_ShRxRyOffMemX16, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SllX16, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SllvRxRy16, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltRxRy16, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltiRxImm16, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltiRxImmX16, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltiuRxImm16, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltiuRxImmX16, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SltuRxRy16, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_T8, 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SraX16, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SravRxRy16, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SrlX16, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SrlvRxRy16, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SubuRxRyRz16, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SwRxRyOffMemX16, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_SwRxSpImmX16, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
		Mips_TEQ, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TEQI, MIPS_INS_TEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_TEQI_MM, MIPS_INS_TEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TEQ_MM, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TGE, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEI, MIPS_INS_TGEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEIU, MIPS_INS_TGEIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEIU_MM, MIPS_INS_TGEIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEI_MM, MIPS_INS_TGEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEU, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TGEU_MM, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TGE_MM, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBP, MIPS_INS_TLBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBP_MM, MIPS_INS_TLBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBR, MIPS_INS_TLBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBR_MM, MIPS_INS_TLBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBWI, MIPS_INS_TLBWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBWI_MM, MIPS_INS_TLBWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBWR, MIPS_INS_TLBWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_TLBWR_MM, MIPS_INS_TLBWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLT, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TLTI, MIPS_INS_TLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_TLTIU_MM, MIPS_INS_TLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLTI_MM, MIPS_INS_TLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLTU, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TLTU_MM, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TLT_MM, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TNE, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TNEI, MIPS_INS_TNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_TNEI_MM, MIPS_INS_TNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TNE_MM, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_L_D64, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_L_S, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_W_D32, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTFP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_W_D64, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_FP64BIT, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_W_MM, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_W_S, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, 0 }, 0, 0
#endif
	},
	{
		Mips_TRUNC_W_S_MM, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_TTLTIU, MIPS_INS_TLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_UDIV, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
		Mips_UDIV_MM, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_HI0, MIPS_REG_LO0, 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_V3MULU, MIPS_INS_V3MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_VMM0, MIPS_INS_VMM0,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_MPL0, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_VMULU, MIPS_INS_VMULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { MIPS_REG_MPL1, MIPS_REG_MPL2, MIPS_REG_P0, MIPS_REG_P1, MIPS_REG_P2, 0 }, { MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_VSHF_B, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_VSHF_D, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_VSHF_H, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_VSHF_W, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_WAIT, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_WAIT_MM, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_WRDSP, MIPS_INS_WRDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
		Mips_WSBH, MIPS_INS_WSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, 0 }, 0, 0
#endif
	},
	{
		Mips_WSBH_MM, MIPS_INS_WSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_XOR, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_XOR64, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_XORI_B, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_XOR_MM, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_XOR_V, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
		Mips_XORi, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_XORi64, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_STDENC, 0 }, 0, 0
#endif
	},
	{
		Mips_XORi_MM, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
		Mips_XorRxRxRy16, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
};

// given internal insn id, return public instruction info
void Mips_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i;

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
				insn->detail->groups[insn->detail->groups_count] = MIPS_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

static const name_map insn_name_maps[] = {
	{ MIPS_INS_INVALID, NULL },

	{ MIPS_INS_ABSQ_S, "absq_s" },
	{ MIPS_INS_ADD, "add" },
	{ MIPS_INS_ADDIUPC, "addiupc" },
	{ MIPS_INS_ADDQH, "addqh" },
	{ MIPS_INS_ADDQH_R, "addqh_r" },
	{ MIPS_INS_ADDQ, "addq" },
	{ MIPS_INS_ADDQ_S, "addq_s" },
	{ MIPS_INS_ADDSC, "addsc" },
	{ MIPS_INS_ADDS_A, "adds_a" },
	{ MIPS_INS_ADDS_S, "adds_s" },
	{ MIPS_INS_ADDS_U, "adds_u" },
	{ MIPS_INS_ADDUH, "adduh" },
	{ MIPS_INS_ADDUH_R, "adduh_r" },
	{ MIPS_INS_ADDU, "addu" },
	{ MIPS_INS_ADDU_S, "addu_s" },
	{ MIPS_INS_ADDVI, "addvi" },
	{ MIPS_INS_ADDV, "addv" },
	{ MIPS_INS_ADDWC, "addwc" },
	{ MIPS_INS_ADD_A, "add_a" },
	{ MIPS_INS_ADDI, "addi" },
	{ MIPS_INS_ADDIU, "addiu" },
	{ MIPS_INS_ALIGN, "align" },
	{ MIPS_INS_ALUIPC, "aluipc" },
	{ MIPS_INS_AND, "and" },
	{ MIPS_INS_ANDI, "andi" },
	{ MIPS_INS_APPEND, "append" },
	{ MIPS_INS_ASUB_S, "asub_s" },
	{ MIPS_INS_ASUB_U, "asub_u" },
	{ MIPS_INS_AUI, "aui" },
	{ MIPS_INS_AUIPC, "auipc" },
	{ MIPS_INS_AVER_S, "aver_s" },
	{ MIPS_INS_AVER_U, "aver_u" },
	{ MIPS_INS_AVE_S, "ave_s" },
	{ MIPS_INS_AVE_U, "ave_u" },
	{ MIPS_INS_BADDU, "baddu" },
	{ MIPS_INS_BAL, "bal" },
	{ MIPS_INS_BALC, "balc" },
	{ MIPS_INS_BALIGN, "balign" },
	{ MIPS_INS_BC, "bc" },
	{ MIPS_INS_BC0F, "bc0f" },
	{ MIPS_INS_BC0FL, "bc0fl" },
	{ MIPS_INS_BC0T, "bc0t" },
	{ MIPS_INS_BC0TL, "bc0tl" },
	{ MIPS_INS_BC1EQZ, "bc1eqz" },
	{ MIPS_INS_BC1F, "bc1f" },
	{ MIPS_INS_BC1FL, "bc1fl" },
	{ MIPS_INS_BC1NEZ, "bc1nez" },
	{ MIPS_INS_BC1T, "bc1t" },
	{ MIPS_INS_BC1TL, "bc1tl" },
	{ MIPS_INS_BC2EQZ, "bc2eqz" },
	{ MIPS_INS_BC2F, "bc2f" },
	{ MIPS_INS_BC2FL, "bc2fl" },
	{ MIPS_INS_BC2NEZ, "bc2nez" },
	{ MIPS_INS_BC2T, "bc2t" },
	{ MIPS_INS_BC2TL, "bc2tl" },
	{ MIPS_INS_BC3F, "bc3f" },
	{ MIPS_INS_BC3FL, "bc3fl" },
	{ MIPS_INS_BC3T, "bc3t" },
	{ MIPS_INS_BC3TL, "bc3tl" },
	{ MIPS_INS_BCLRI, "bclri" },
	{ MIPS_INS_BCLR, "bclr" },
	{ MIPS_INS_BEQ, "beq" },
	{ MIPS_INS_BEQC, "beqc" },
	{ MIPS_INS_BEQL, "beql" },
	{ MIPS_INS_BEQZALC, "beqzalc" },
	{ MIPS_INS_BEQZC, "beqzc" },
	{ MIPS_INS_BGEC, "bgec" },
	{ MIPS_INS_BGEUC, "bgeuc" },
	{ MIPS_INS_BGEZ, "bgez" },
	{ MIPS_INS_BGEZAL, "bgezal" },
	{ MIPS_INS_BGEZALC, "bgezalc" },
	{ MIPS_INS_BGEZALL, "bgezall" },
	{ MIPS_INS_BGEZALS, "bgezals" },
	{ MIPS_INS_BGEZC, "bgezc" },
	{ MIPS_INS_BGEZL, "bgezl" },
	{ MIPS_INS_BGTZ, "bgtz" },
	{ MIPS_INS_BGTZALC, "bgtzalc" },
	{ MIPS_INS_BGTZC, "bgtzc" },
	{ MIPS_INS_BGTZL, "bgtzl" },
	{ MIPS_INS_BINSLI, "binsli" },
	{ MIPS_INS_BINSL, "binsl" },
	{ MIPS_INS_BINSRI, "binsri" },
	{ MIPS_INS_BINSR, "binsr" },
	{ MIPS_INS_BITREV, "bitrev" },
	{ MIPS_INS_BITSWAP, "bitswap" },
	{ MIPS_INS_BLEZ, "blez" },
	{ MIPS_INS_BLEZALC, "blezalc" },
	{ MIPS_INS_BLEZC, "blezc" },
	{ MIPS_INS_BLEZL, "blezl" },
	{ MIPS_INS_BLTC, "bltc" },
	{ MIPS_INS_BLTUC, "bltuc" },
	{ MIPS_INS_BLTZ, "bltz" },
	{ MIPS_INS_BLTZAL, "bltzal" },
	{ MIPS_INS_BLTZALC, "bltzalc" },
	{ MIPS_INS_BLTZALL, "bltzall" },
	{ MIPS_INS_BLTZALS, "bltzals" },
	{ MIPS_INS_BLTZC, "bltzc" },
	{ MIPS_INS_BLTZL, "bltzl" },
	{ MIPS_INS_BMNZI, "bmnzi" },
	{ MIPS_INS_BMNZ, "bmnz" },
	{ MIPS_INS_BMZI, "bmzi" },
	{ MIPS_INS_BMZ, "bmz" },
	{ MIPS_INS_BNE, "bne" },
	{ MIPS_INS_BNEC, "bnec" },
	{ MIPS_INS_BNEGI, "bnegi" },
	{ MIPS_INS_BNEG, "bneg" },
	{ MIPS_INS_BNEL, "bnel" },
	{ MIPS_INS_BNEZALC, "bnezalc" },
	{ MIPS_INS_BNEZC, "bnezc" },
	{ MIPS_INS_BNVC, "bnvc" },
	{ MIPS_INS_BNZ, "bnz" },
	{ MIPS_INS_BOVC, "bovc" },
	{ MIPS_INS_BPOSGE32, "bposge32" },
	{ MIPS_INS_BREAK, "break" },
	{ MIPS_INS_BSELI, "bseli" },
	{ MIPS_INS_BSEL, "bsel" },
	{ MIPS_INS_BSETI, "bseti" },
	{ MIPS_INS_BSET, "bset" },
	{ MIPS_INS_BZ, "bz" },
	{ MIPS_INS_BEQZ, "beqz" },
	{ MIPS_INS_B, "b" },
	{ MIPS_INS_BNEZ, "bnez" },
	{ MIPS_INS_BTEQZ, "bteqz" },
	{ MIPS_INS_BTNEZ, "btnez" },
	{ MIPS_INS_CACHE, "cache" },
	{ MIPS_INS_CEIL, "ceil" },
	{ MIPS_INS_CEQI, "ceqi" },
	{ MIPS_INS_CEQ, "ceq" },
	{ MIPS_INS_CFC1, "cfc1" },
	{ MIPS_INS_CFCMSA, "cfcmsa" },
	{ MIPS_INS_CINS, "cins" },
	{ MIPS_INS_CINS32, "cins32" },
	{ MIPS_INS_CLASS, "class" },
	{ MIPS_INS_CLEI_S, "clei_s" },
	{ MIPS_INS_CLEI_U, "clei_u" },
	{ MIPS_INS_CLE_S, "cle_s" },
	{ MIPS_INS_CLE_U, "cle_u" },
	{ MIPS_INS_CLO, "clo" },
	{ MIPS_INS_CLTI_S, "clti_s" },
	{ MIPS_INS_CLTI_U, "clti_u" },
	{ MIPS_INS_CLT_S, "clt_s" },
	{ MIPS_INS_CLT_U, "clt_u" },
	{ MIPS_INS_CLZ, "clz" },
	{ MIPS_INS_CMPGDU, "cmpgdu" },
	{ MIPS_INS_CMPGU, "cmpgu" },
	{ MIPS_INS_CMPU, "cmpu" },
	{ MIPS_INS_CMP, "cmp" },
	{ MIPS_INS_COPY_S, "copy_s" },
	{ MIPS_INS_COPY_U, "copy_u" },
	{ MIPS_INS_CTC1, "ctc1" },
	{ MIPS_INS_CTCMSA, "ctcmsa" },
	{ MIPS_INS_CVT, "cvt" },
	{ MIPS_INS_C, "c" },
	{ MIPS_INS_CMPI, "cmpi" },
	{ MIPS_INS_DADD, "dadd" },
	{ MIPS_INS_DADDI, "daddi" },
	{ MIPS_INS_DADDIU, "daddiu" },
	{ MIPS_INS_DADDU, "daddu" },
	{ MIPS_INS_DAHI, "dahi" },
	{ MIPS_INS_DALIGN, "dalign" },
	{ MIPS_INS_DATI, "dati" },
	{ MIPS_INS_DAUI, "daui" },
	{ MIPS_INS_DBITSWAP, "dbitswap" },
	{ MIPS_INS_DCLO, "dclo" },
	{ MIPS_INS_DCLZ, "dclz" },
	{ MIPS_INS_DDIV, "ddiv" },
	{ MIPS_INS_DDIVU, "ddivu" },
	{ MIPS_INS_DERET, "deret" },
	{ MIPS_INS_DEXT, "dext" },
	{ MIPS_INS_DEXTM, "dextm" },
	{ MIPS_INS_DEXTU, "dextu" },
	{ MIPS_INS_DI, "di" },
	{ MIPS_INS_DINS, "dins" },
	{ MIPS_INS_DINSM, "dinsm" },
	{ MIPS_INS_DINSU, "dinsu" },
	{ MIPS_INS_DIV, "div" },
	{ MIPS_INS_DIVU, "divu" },
	{ MIPS_INS_DIV_S, "div_s" },
	{ MIPS_INS_DIV_U, "div_u" },
	{ MIPS_INS_DLSA, "dlsa" },
	{ MIPS_INS_DMFC0, "dmfc0" },
	{ MIPS_INS_DMFC1, "dmfc1" },
	{ MIPS_INS_DMFC2, "dmfc2" },
	{ MIPS_INS_DMOD, "dmod" },
	{ MIPS_INS_DMODU, "dmodu" },
	{ MIPS_INS_DMTC0, "dmtc0" },
	{ MIPS_INS_DMTC1, "dmtc1" },
	{ MIPS_INS_DMTC2, "dmtc2" },
	{ MIPS_INS_DMUH, "dmuh" },
	{ MIPS_INS_DMUHU, "dmuhu" },
	{ MIPS_INS_DMUL, "dmul" },
	{ MIPS_INS_DMULT, "dmult" },
	{ MIPS_INS_DMULTU, "dmultu" },
	{ MIPS_INS_DMULU, "dmulu" },
	{ MIPS_INS_DOTP_S, "dotp_s" },
	{ MIPS_INS_DOTP_U, "dotp_u" },
	{ MIPS_INS_DPADD_S, "dpadd_s" },
	{ MIPS_INS_DPADD_U, "dpadd_u" },
	{ MIPS_INS_DPAQX_SA, "dpaqx_sa" },
	{ MIPS_INS_DPAQX_S, "dpaqx_s" },
	{ MIPS_INS_DPAQ_SA, "dpaq_sa" },
	{ MIPS_INS_DPAQ_S, "dpaq_s" },
	{ MIPS_INS_DPAU, "dpau" },
	{ MIPS_INS_DPAX, "dpax" },
	{ MIPS_INS_DPA, "dpa" },
	{ MIPS_INS_DPOP, "dpop" },
	{ MIPS_INS_DPSQX_SA, "dpsqx_sa" },
	{ MIPS_INS_DPSQX_S, "dpsqx_s" },
	{ MIPS_INS_DPSQ_SA, "dpsq_sa" },
	{ MIPS_INS_DPSQ_S, "dpsq_s" },
	{ MIPS_INS_DPSUB_S, "dpsub_s" },
	{ MIPS_INS_DPSUB_U, "dpsub_u" },
	{ MIPS_INS_DPSU, "dpsu" },
	{ MIPS_INS_DPSX, "dpsx" },
	{ MIPS_INS_DPS, "dps" },
	{ MIPS_INS_DROTR, "drotr" },
	{ MIPS_INS_DROTR32, "drotr32" },
	{ MIPS_INS_DROTRV, "drotrv" },
	{ MIPS_INS_DSBH, "dsbh" },
	{ MIPS_INS_DSHD, "dshd" },
	{ MIPS_INS_DSLL, "dsll" },
	{ MIPS_INS_DSLL32, "dsll32" },
	{ MIPS_INS_DSLLV, "dsllv" },
	{ MIPS_INS_DSRA, "dsra" },
	{ MIPS_INS_DSRA32, "dsra32" },
	{ MIPS_INS_DSRAV, "dsrav" },
	{ MIPS_INS_DSRL, "dsrl" },
	{ MIPS_INS_DSRL32, "dsrl32" },
	{ MIPS_INS_DSRLV, "dsrlv" },
	{ MIPS_INS_DSUB, "dsub" },
	{ MIPS_INS_DSUBU, "dsubu" },
	{ MIPS_INS_EHB, "ehb" },
	{ MIPS_INS_EI, "ei" },
	{ MIPS_INS_ERET, "eret" },
	{ MIPS_INS_EXT, "ext" },
	{ MIPS_INS_EXTP, "extp" },
	{ MIPS_INS_EXTPDP, "extpdp" },
	{ MIPS_INS_EXTPDPV, "extpdpv" },
	{ MIPS_INS_EXTPV, "extpv" },
	{ MIPS_INS_EXTRV_RS, "extrv_rs" },
	{ MIPS_INS_EXTRV_R, "extrv_r" },
	{ MIPS_INS_EXTRV_S, "extrv_s" },
	{ MIPS_INS_EXTRV, "extrv" },
	{ MIPS_INS_EXTR_RS, "extr_rs" },
	{ MIPS_INS_EXTR_R, "extr_r" },
	{ MIPS_INS_EXTR_S, "extr_s" },
	{ MIPS_INS_EXTR, "extr" },
	{ MIPS_INS_EXTS, "exts" },
	{ MIPS_INS_EXTS32, "exts32" },
	{ MIPS_INS_ABS, "abs" },
	{ MIPS_INS_FADD, "fadd" },
	{ MIPS_INS_FCAF, "fcaf" },
	{ MIPS_INS_FCEQ, "fceq" },
	{ MIPS_INS_FCLASS, "fclass" },
	{ MIPS_INS_FCLE, "fcle" },
	{ MIPS_INS_FCLT, "fclt" },
	{ MIPS_INS_FCNE, "fcne" },
	{ MIPS_INS_FCOR, "fcor" },
	{ MIPS_INS_FCUEQ, "fcueq" },
	{ MIPS_INS_FCULE, "fcule" },
	{ MIPS_INS_FCULT, "fcult" },
	{ MIPS_INS_FCUNE, "fcune" },
	{ MIPS_INS_FCUN, "fcun" },
	{ MIPS_INS_FDIV, "fdiv" },
	{ MIPS_INS_FEXDO, "fexdo" },
	{ MIPS_INS_FEXP2, "fexp2" },
	{ MIPS_INS_FEXUPL, "fexupl" },
	{ MIPS_INS_FEXUPR, "fexupr" },
	{ MIPS_INS_FFINT_S, "ffint_s" },
	{ MIPS_INS_FFINT_U, "ffint_u" },
	{ MIPS_INS_FFQL, "ffql" },
	{ MIPS_INS_FFQR, "ffqr" },
	{ MIPS_INS_FILL, "fill" },
	{ MIPS_INS_FLOG2, "flog2" },
	{ MIPS_INS_FLOOR, "floor" },
	{ MIPS_INS_FMADD, "fmadd" },
	{ MIPS_INS_FMAX_A, "fmax_a" },
	{ MIPS_INS_FMAX, "fmax" },
	{ MIPS_INS_FMIN_A, "fmin_a" },
	{ MIPS_INS_FMIN, "fmin" },
	{ MIPS_INS_MOV, "mov" },
	{ MIPS_INS_FMSUB, "fmsub" },
	{ MIPS_INS_FMUL, "fmul" },
	{ MIPS_INS_MUL, "mul" },
	{ MIPS_INS_NEG, "neg" },
	{ MIPS_INS_FRCP, "frcp" },
	{ MIPS_INS_FRINT, "frint" },
	{ MIPS_INS_FRSQRT, "frsqrt" },
	{ MIPS_INS_FSAF, "fsaf" },
	{ MIPS_INS_FSEQ, "fseq" },
	{ MIPS_INS_FSLE, "fsle" },
	{ MIPS_INS_FSLT, "fslt" },
	{ MIPS_INS_FSNE, "fsne" },
	{ MIPS_INS_FSOR, "fsor" },
	{ MIPS_INS_FSQRT, "fsqrt" },
	{ MIPS_INS_SQRT, "sqrt" },
	{ MIPS_INS_FSUB, "fsub" },
	{ MIPS_INS_SUB, "sub" },
	{ MIPS_INS_FSUEQ, "fsueq" },
	{ MIPS_INS_FSULE, "fsule" },
	{ MIPS_INS_FSULT, "fsult" },
	{ MIPS_INS_FSUNE, "fsune" },
	{ MIPS_INS_FSUN, "fsun" },
	{ MIPS_INS_FTINT_S, "ftint_s" },
	{ MIPS_INS_FTINT_U, "ftint_u" },
	{ MIPS_INS_FTQ, "ftq" },
	{ MIPS_INS_FTRUNC_S, "ftrunc_s" },
	{ MIPS_INS_FTRUNC_U, "ftrunc_u" },
	{ MIPS_INS_HADD_S, "hadd_s" },
	{ MIPS_INS_HADD_U, "hadd_u" },
	{ MIPS_INS_HSUB_S, "hsub_s" },
	{ MIPS_INS_HSUB_U, "hsub_u" },
	{ MIPS_INS_ILVEV, "ilvev" },
	{ MIPS_INS_ILVL, "ilvl" },
	{ MIPS_INS_ILVOD, "ilvod" },
	{ MIPS_INS_ILVR, "ilvr" },
	{ MIPS_INS_INS, "ins" },
	{ MIPS_INS_INSERT, "insert" },
	{ MIPS_INS_INSV, "insv" },
	{ MIPS_INS_INSVE, "insve" },
	{ MIPS_INS_J, "j" },
	{ MIPS_INS_JAL, "jal" },
	{ MIPS_INS_JALR, "jalr" },
	{ MIPS_INS_JALRS, "jalrs" },
	{ MIPS_INS_JALS, "jals" },
	{ MIPS_INS_JALX, "jalx" },
	{ MIPS_INS_JIALC, "jialc" },
	{ MIPS_INS_JIC, "jic" },
	{ MIPS_INS_JR, "jr" },
	{ MIPS_INS_JRADDIUSP, "jraddiusp" },
	{ MIPS_INS_JRC, "jrc" },
	{ MIPS_INS_JALRC, "jalrc" },
	{ MIPS_INS_LB, "lb" },
	{ MIPS_INS_LBUX, "lbux" },
	{ MIPS_INS_LBU, "lbu" },
	{ MIPS_INS_LD, "ld" },
	{ MIPS_INS_LDC1, "ldc1" },
	{ MIPS_INS_LDC2, "ldc2" },
	{ MIPS_INS_LDC3, "ldc3" },
	{ MIPS_INS_LDI, "ldi" },
	{ MIPS_INS_LDL, "ldl" },
	{ MIPS_INS_LDPC, "ldpc" },
	{ MIPS_INS_LDR, "ldr" },
	{ MIPS_INS_LDXC1, "ldxc1" },
	{ MIPS_INS_LH, "lh" },
	{ MIPS_INS_LHX, "lhx" },
	{ MIPS_INS_LHU, "lhu" },
	{ MIPS_INS_LL, "ll" },
	{ MIPS_INS_LLD, "lld" },
	{ MIPS_INS_LSA, "lsa" },
	{ MIPS_INS_LUXC1, "luxc1" },
	{ MIPS_INS_LUI, "lui" },
	{ MIPS_INS_LW, "lw" },
	{ MIPS_INS_LWC1, "lwc1" },
	{ MIPS_INS_LWC2, "lwc2" },
	{ MIPS_INS_LWC3, "lwc3" },
	{ MIPS_INS_LWL, "lwl" },
	{ MIPS_INS_LWPC, "lwpc" },
	{ MIPS_INS_LWR, "lwr" },
	{ MIPS_INS_LWUPC, "lwupc" },
	{ MIPS_INS_LWU, "lwu" },
	{ MIPS_INS_LWX, "lwx" },
	{ MIPS_INS_LWXC1, "lwxc1" },
	{ MIPS_INS_LI, "li" },
	{ MIPS_INS_MADD, "madd" },
	{ MIPS_INS_MADDF, "maddf" },
	{ MIPS_INS_MADDR_Q, "maddr_q" },
	{ MIPS_INS_MADDU, "maddu" },
	{ MIPS_INS_MADDV, "maddv" },
	{ MIPS_INS_MADD_Q, "madd_q" },
	{ MIPS_INS_MAQ_SA, "maq_sa" },
	{ MIPS_INS_MAQ_S, "maq_s" },
	{ MIPS_INS_MAXA, "maxa" },
	{ MIPS_INS_MAXI_S, "maxi_s" },
	{ MIPS_INS_MAXI_U, "maxi_u" },
	{ MIPS_INS_MAX_A, "max_a" },
	{ MIPS_INS_MAX, "max" },
	{ MIPS_INS_MAX_S, "max_s" },
	{ MIPS_INS_MAX_U, "max_u" },
	{ MIPS_INS_MFC0, "mfc0" },
	{ MIPS_INS_MFC1, "mfc1" },
	{ MIPS_INS_MFC2, "mfc2" },
	{ MIPS_INS_MFHC1, "mfhc1" },
	{ MIPS_INS_MFHI, "mfhi" },
	{ MIPS_INS_MFLO, "mflo" },
	{ MIPS_INS_MINA, "mina" },
	{ MIPS_INS_MINI_S, "mini_s" },
	{ MIPS_INS_MINI_U, "mini_u" },
	{ MIPS_INS_MIN_A, "min_a" },
	{ MIPS_INS_MIN, "min" },
	{ MIPS_INS_MIN_S, "min_s" },
	{ MIPS_INS_MIN_U, "min_u" },
	{ MIPS_INS_MOD, "mod" },
	{ MIPS_INS_MODSUB, "modsub" },
	{ MIPS_INS_MODU, "modu" },
	{ MIPS_INS_MOD_S, "mod_s" },
	{ MIPS_INS_MOD_U, "mod_u" },
	{ MIPS_INS_MOVE, "move" },
	{ MIPS_INS_MOVF, "movf" },
	{ MIPS_INS_MOVN, "movn" },
	{ MIPS_INS_MOVT, "movt" },
	{ MIPS_INS_MOVZ, "movz" },
	{ MIPS_INS_MSUB, "msub" },
	{ MIPS_INS_MSUBF, "msubf" },
	{ MIPS_INS_MSUBR_Q, "msubr_q" },
	{ MIPS_INS_MSUBU, "msubu" },
	{ MIPS_INS_MSUBV, "msubv" },
	{ MIPS_INS_MSUB_Q, "msub_q" },
	{ MIPS_INS_MTC0, "mtc0" },
	{ MIPS_INS_MTC1, "mtc1" },
	{ MIPS_INS_MTC2, "mtc2" },
	{ MIPS_INS_MTHC1, "mthc1" },
	{ MIPS_INS_MTHI, "mthi" },
	{ MIPS_INS_MTHLIP, "mthlip" },
	{ MIPS_INS_MTLO, "mtlo" },
	{ MIPS_INS_MTM0, "mtm0" },
	{ MIPS_INS_MTM1, "mtm1" },
	{ MIPS_INS_MTM2, "mtm2" },
	{ MIPS_INS_MTP0, "mtp0" },
	{ MIPS_INS_MTP1, "mtp1" },
	{ MIPS_INS_MTP2, "mtp2" },
	{ MIPS_INS_MUH, "muh" },
	{ MIPS_INS_MUHU, "muhu" },
	{ MIPS_INS_MULEQ_S, "muleq_s" },
	{ MIPS_INS_MULEU_S, "muleu_s" },
	{ MIPS_INS_MULQ_RS, "mulq_rs" },
	{ MIPS_INS_MULQ_S, "mulq_s" },
	{ MIPS_INS_MULR_Q, "mulr_q" },
	{ MIPS_INS_MULSAQ_S, "mulsaq_s" },
	{ MIPS_INS_MULSA, "mulsa" },
	{ MIPS_INS_MULT, "mult" },
	{ MIPS_INS_MULTU, "multu" },
	{ MIPS_INS_MULU, "mulu" },
	{ MIPS_INS_MULV, "mulv" },
	{ MIPS_INS_MUL_Q, "mul_q" },
	{ MIPS_INS_MUL_S, "mul_s" },
	{ MIPS_INS_NLOC, "nloc" },
	{ MIPS_INS_NLZC, "nlzc" },
	{ MIPS_INS_NMADD, "nmadd" },
	{ MIPS_INS_NMSUB, "nmsub" },
	{ MIPS_INS_NOR, "nor" },
	{ MIPS_INS_NORI, "nori" },
	{ MIPS_INS_NOT, "not" },
	{ MIPS_INS_OR, "or" },
	{ MIPS_INS_ORI, "ori" },
	{ MIPS_INS_PACKRL, "packrl" },
	{ MIPS_INS_PAUSE, "pause" },
	{ MIPS_INS_PCKEV, "pckev" },
	{ MIPS_INS_PCKOD, "pckod" },
	{ MIPS_INS_PCNT, "pcnt" },
	{ MIPS_INS_PICK, "pick" },
	{ MIPS_INS_POP, "pop" },
	{ MIPS_INS_PRECEQU, "precequ" },
	{ MIPS_INS_PRECEQ, "preceq" },
	{ MIPS_INS_PRECEU, "preceu" },
	{ MIPS_INS_PRECRQU_S, "precrqu_s" },
	{ MIPS_INS_PRECRQ, "precrq" },
	{ MIPS_INS_PRECRQ_RS, "precrq_rs" },
	{ MIPS_INS_PRECR, "precr" },
	{ MIPS_INS_PRECR_SRA, "precr_sra" },
	{ MIPS_INS_PRECR_SRA_R, "precr_sra_r" },
	{ MIPS_INS_PREF, "pref" },
	{ MIPS_INS_PREPEND, "prepend" },
	{ MIPS_INS_RADDU, "raddu" },
	{ MIPS_INS_RDDSP, "rddsp" },
	{ MIPS_INS_RDHWR, "rdhwr" },
	{ MIPS_INS_REPLV, "replv" },
	{ MIPS_INS_REPL, "repl" },
	{ MIPS_INS_RINT, "rint" },
	{ MIPS_INS_ROTR, "rotr" },
	{ MIPS_INS_ROTRV, "rotrv" },
	{ MIPS_INS_ROUND, "round" },
	{ MIPS_INS_SAT_S, "sat_s" },
	{ MIPS_INS_SAT_U, "sat_u" },
	{ MIPS_INS_SB, "sb" },
	{ MIPS_INS_SC, "sc" },
	{ MIPS_INS_SCD, "scd" },
	{ MIPS_INS_SD, "sd" },
	{ MIPS_INS_SDBBP, "sdbbp" },
	{ MIPS_INS_SDC1, "sdc1" },
	{ MIPS_INS_SDC2, "sdc2" },
	{ MIPS_INS_SDC3, "sdc3" },
	{ MIPS_INS_SDL, "sdl" },
	{ MIPS_INS_SDR, "sdr" },
	{ MIPS_INS_SDXC1, "sdxc1" },
	{ MIPS_INS_SEB, "seb" },
	{ MIPS_INS_SEH, "seh" },
	{ MIPS_INS_SELEQZ, "seleqz" },
	{ MIPS_INS_SELNEZ, "selnez" },
	{ MIPS_INS_SEL, "sel" },
	{ MIPS_INS_SEQ, "seq" },
	{ MIPS_INS_SEQI, "seqi" },
	{ MIPS_INS_SH, "sh" },
	{ MIPS_INS_SHF, "shf" },
	{ MIPS_INS_SHILO, "shilo" },
	{ MIPS_INS_SHILOV, "shilov" },
	{ MIPS_INS_SHLLV, "shllv" },
	{ MIPS_INS_SHLLV_S, "shllv_s" },
	{ MIPS_INS_SHLL, "shll" },
	{ MIPS_INS_SHLL_S, "shll_s" },
	{ MIPS_INS_SHRAV, "shrav" },
	{ MIPS_INS_SHRAV_R, "shrav_r" },
	{ MIPS_INS_SHRA, "shra" },
	{ MIPS_INS_SHRA_R, "shra_r" },
	{ MIPS_INS_SHRLV, "shrlv" },
	{ MIPS_INS_SHRL, "shrl" },
	{ MIPS_INS_SLDI, "sldi" },
	{ MIPS_INS_SLD, "sld" },
	{ MIPS_INS_SLL, "sll" },
	{ MIPS_INS_SLLI, "slli" },
	{ MIPS_INS_SLLV, "sllv" },
	{ MIPS_INS_SLT, "slt" },
	{ MIPS_INS_SLTI, "slti" },
	{ MIPS_INS_SLTIU, "sltiu" },
	{ MIPS_INS_SLTU, "sltu" },
	{ MIPS_INS_SNE, "sne" },
	{ MIPS_INS_SNEI, "snei" },
	{ MIPS_INS_SPLATI, "splati" },
	{ MIPS_INS_SPLAT, "splat" },
	{ MIPS_INS_SRA, "sra" },
	{ MIPS_INS_SRAI, "srai" },
	{ MIPS_INS_SRARI, "srari" },
	{ MIPS_INS_SRAR, "srar" },
	{ MIPS_INS_SRAV, "srav" },
	{ MIPS_INS_SRL, "srl" },
	{ MIPS_INS_SRLI, "srli" },
	{ MIPS_INS_SRLRI, "srlri" },
	{ MIPS_INS_SRLR, "srlr" },
	{ MIPS_INS_SRLV, "srlv" },
	{ MIPS_INS_SSNOP, "ssnop" },
	{ MIPS_INS_ST, "st" },
	{ MIPS_INS_SUBQH, "subqh" },
	{ MIPS_INS_SUBQH_R, "subqh_r" },
	{ MIPS_INS_SUBQ, "subq" },
	{ MIPS_INS_SUBQ_S, "subq_s" },
	{ MIPS_INS_SUBSUS_U, "subsus_u" },
	{ MIPS_INS_SUBSUU_S, "subsuu_s" },
	{ MIPS_INS_SUBS_S, "subs_s" },
	{ MIPS_INS_SUBS_U, "subs_u" },
	{ MIPS_INS_SUBUH, "subuh" },
	{ MIPS_INS_SUBUH_R, "subuh_r" },
	{ MIPS_INS_SUBU, "subu" },
	{ MIPS_INS_SUBU_S, "subu_s" },
	{ MIPS_INS_SUBVI, "subvi" },
	{ MIPS_INS_SUBV, "subv" },
	{ MIPS_INS_SUXC1, "suxc1" },
	{ MIPS_INS_SW, "sw" },
	{ MIPS_INS_SWC1, "swc1" },
	{ MIPS_INS_SWC2, "swc2" },
	{ MIPS_INS_SWC3, "swc3" },
	{ MIPS_INS_SWL, "swl" },
	{ MIPS_INS_SWR, "swr" },
	{ MIPS_INS_SWXC1, "swxc1" },
	{ MIPS_INS_SYNC, "sync" },
	{ MIPS_INS_SYSCALL, "syscall" },
	{ MIPS_INS_TEQ, "teq" },
	{ MIPS_INS_TEQI, "teqi" },
	{ MIPS_INS_TGE, "tge" },
	{ MIPS_INS_TGEI, "tgei" },
	{ MIPS_INS_TGEIU, "tgeiu" },
	{ MIPS_INS_TGEU, "tgeu" },
	{ MIPS_INS_TLBP, "tlbp" },
	{ MIPS_INS_TLBR, "tlbr" },
	{ MIPS_INS_TLBWI, "tlbwi" },
	{ MIPS_INS_TLBWR, "tlbwr" },
	{ MIPS_INS_TLT, "tlt" },
	{ MIPS_INS_TLTI, "tlti" },
	{ MIPS_INS_TLTIU, "tltiu" },
	{ MIPS_INS_TLTU, "tltu" },
	{ MIPS_INS_TNE, "tne" },
	{ MIPS_INS_TNEI, "tnei" },
	{ MIPS_INS_TRUNC, "trunc" },
	{ MIPS_INS_V3MULU, "v3mulu" },
	{ MIPS_INS_VMM0, "vmm0" },
	{ MIPS_INS_VMULU, "vmulu" },
	{ MIPS_INS_VSHF, "vshf" },
	{ MIPS_INS_WAIT, "wait" },
	{ MIPS_INS_WRDSP, "wrdsp" },
	{ MIPS_INS_WSBH, "wsbh" },
	{ MIPS_INS_XOR, "xor" },
	{ MIPS_INS_XORI, "xori" },

	// alias instructions
	{ MIPS_INS_NOP, "nop" },
	{ MIPS_INS_NEGU, "negu" },

	{ MIPS_INS_JALR_HB, "jalr.hb" },
	{ MIPS_INS_JR_HB, "jr.hb" },
};

const char *Mips_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= MIPS_INS_ENDING)
		return NULL;

	return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ MIPS_GRP_INVALID, NULL },
	{ MIPS_GRP_JUMP, "jump" },

	// architecture-specific groups
	{ MIPS_GRP_BITCOUNT, "bitcount" },
	{ MIPS_GRP_DSP, "dsp" },
	{ MIPS_GRP_DSPR2, "dspr2" },
	{ MIPS_GRP_FPIDX, "fpidx" },
	{ MIPS_GRP_MSA, "msa" },
	{ MIPS_GRP_MIPS32R2, "mips32r2" },
	{ MIPS_GRP_MIPS64, "mips64" },
	{ MIPS_GRP_MIPS64R2, "mips64r2" },
	{ MIPS_GRP_SEINREG, "seinreg" },
	{ MIPS_GRP_STDENC, "stdenc" },
	{ MIPS_GRP_SWAP, "swap" },
	{ MIPS_GRP_MICROMIPS, "micromips" },
	{ MIPS_GRP_MIPS16MODE, "mips16mode" },
	{ MIPS_GRP_FP64BIT, "fp64bit" },
	{ MIPS_GRP_NONANSFPMATH, "nonansfpmath" },
	{ MIPS_GRP_NOTFP64BIT, "notfp64bit" },
	{ MIPS_GRP_NOTINMICROMIPS, "notinmicromips" },
	{ MIPS_GRP_NOTNACL, "notnacl" },

	{ MIPS_GRP_NOTMIPS32R6, "notmips32r6" },
	{ MIPS_GRP_NOTMIPS64R6, "notmips64r6" },
	{ MIPS_GRP_CNMIPS, "cnmips" },

	{ MIPS_GRP_MIPS32, "mips32" },
	{ MIPS_GRP_MIPS32R6, "mips32r6" },
	{ MIPS_GRP_MIPS64R6, "mips64r6" },

	{ MIPS_GRP_MIPS2, "mips2" },
	{ MIPS_GRP_MIPS3, "mips3" },
	{ MIPS_GRP_MIPS3_32, "mips3_32"},
	{ MIPS_GRP_MIPS3_32R2, "mips3_32r2" },

	{ MIPS_GRP_MIPS4_32, "mips4_32" },
	{ MIPS_GRP_MIPS4_32R2, "mips4_32r2" },
	{ MIPS_GRP_MIPS5_32R2, "mips5_32r2" },

	{ MIPS_GRP_GP32BIT, "gp32bit" },
	{ MIPS_GRP_GP64BIT, "gp64bit" },
};
#endif

const char *Mips_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= MIPS_GRP_ENDING || (id > MIPS_GRP_JUMP && id < MIPS_GRP_BITCOUNT))
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

// map instruction name to public instruction ID
mips_reg Mips_map_insn(const char *name)
{
	// handle special alias first
	unsigned int i;

	// NOTE: skip first NULL name in insn_name_maps
	i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	return (i != -1)? i : MIPS_REG_INVALID;
}

// map internal raw register to 'public' register
mips_reg Mips_map_register(unsigned int r)
{
	// for some reasons different Mips modes can map different register number to
	// the same Mips register. this function handles the issue for exposing Mips
	// operands by mapping internal registers to 'public' register.
	static const unsigned int map[] = { 0,
		MIPS_REG_AT, MIPS_REG_DSPCCOND, MIPS_REG_DSPCARRY, MIPS_REG_DSPEFI, MIPS_REG_DSPOUTFLAG,
		MIPS_REG_DSPPOS, MIPS_REG_DSPSCOUNT, MIPS_REG_FP, MIPS_REG_GP, MIPS_REG_2,
		MIPS_REG_1, MIPS_REG_0, MIPS_REG_6, MIPS_REG_4, MIPS_REG_5,
		MIPS_REG_3, MIPS_REG_7, 0, MIPS_REG_RA, MIPS_REG_SP,
		MIPS_REG_ZERO, MIPS_REG_A0, MIPS_REG_A1, MIPS_REG_A2, MIPS_REG_A3,
		MIPS_REG_AC0, MIPS_REG_AC1, MIPS_REG_AC2, MIPS_REG_AC3, MIPS_REG_AT,
		MIPS_REG_CC0, MIPS_REG_CC1, MIPS_REG_CC2, MIPS_REG_CC3, MIPS_REG_CC4,
		MIPS_REG_CC5, MIPS_REG_CC6, MIPS_REG_CC7, MIPS_REG_0, MIPS_REG_1,
		MIPS_REG_2, MIPS_REG_3, MIPS_REG_4, MIPS_REG_5, MIPS_REG_6,
		MIPS_REG_7, MIPS_REG_8, MIPS_REG_9, MIPS_REG_0, MIPS_REG_1,
		MIPS_REG_2, MIPS_REG_3, MIPS_REG_4, MIPS_REG_5, MIPS_REG_6,
		MIPS_REG_7, MIPS_REG_8, MIPS_REG_9, MIPS_REG_10, MIPS_REG_11,
		MIPS_REG_12, MIPS_REG_13, MIPS_REG_14, MIPS_REG_15, MIPS_REG_16,
		MIPS_REG_17, MIPS_REG_18, MIPS_REG_19, MIPS_REG_20, MIPS_REG_21,
		MIPS_REG_22, MIPS_REG_23, MIPS_REG_24, MIPS_REG_25, MIPS_REG_26,
		MIPS_REG_27, MIPS_REG_28, MIPS_REG_29, MIPS_REG_30, MIPS_REG_31,
		MIPS_REG_10, MIPS_REG_11, MIPS_REG_12, MIPS_REG_13, MIPS_REG_14,
		MIPS_REG_15, MIPS_REG_16, MIPS_REG_17, MIPS_REG_18, MIPS_REG_19,
		MIPS_REG_20, MIPS_REG_21, MIPS_REG_22, MIPS_REG_23, MIPS_REG_24,
		MIPS_REG_25, MIPS_REG_26, MIPS_REG_27, MIPS_REG_28, MIPS_REG_29,
		MIPS_REG_30, MIPS_REG_31, MIPS_REG_F0, MIPS_REG_F2, MIPS_REG_F4,
		MIPS_REG_F6, MIPS_REG_F8, MIPS_REG_F10, MIPS_REG_F12, MIPS_REG_F14,
		MIPS_REG_F16, MIPS_REG_F18, MIPS_REG_F20, MIPS_REG_F22, MIPS_REG_F24,
		MIPS_REG_F26, MIPS_REG_F28, MIPS_REG_F30, MIPS_REG_DSPOUTFLAG20, MIPS_REG_DSPOUTFLAG21,
		MIPS_REG_DSPOUTFLAG22, MIPS_REG_DSPOUTFLAG23, MIPS_REG_F0, MIPS_REG_F1, MIPS_REG_F2,
		MIPS_REG_F3, MIPS_REG_F4, MIPS_REG_F5, MIPS_REG_F6, MIPS_REG_F7,
		MIPS_REG_F8, MIPS_REG_F9, MIPS_REG_F10, MIPS_REG_F11, MIPS_REG_F12,
		MIPS_REG_F13, MIPS_REG_F14, MIPS_REG_F15, MIPS_REG_F16, MIPS_REG_F17,
		MIPS_REG_F18, MIPS_REG_F19, MIPS_REG_F20, MIPS_REG_F21, MIPS_REG_F22,
		MIPS_REG_F23, MIPS_REG_F24, MIPS_REG_F25, MIPS_REG_F26, MIPS_REG_F27,
		MIPS_REG_F28, MIPS_REG_F29, MIPS_REG_F30, MIPS_REG_F31, MIPS_REG_FCC0,
		MIPS_REG_FCC1, MIPS_REG_FCC2, MIPS_REG_FCC3, MIPS_REG_FCC4, MIPS_REG_FCC5,
		MIPS_REG_FCC6, MIPS_REG_FCC7, MIPS_REG_0, MIPS_REG_1, MIPS_REG_2,
		MIPS_REG_3, MIPS_REG_4, MIPS_REG_5, MIPS_REG_6, MIPS_REG_7,
		MIPS_REG_8, MIPS_REG_9, MIPS_REG_10, MIPS_REG_11, MIPS_REG_12,
		MIPS_REG_13, MIPS_REG_14, MIPS_REG_15, MIPS_REG_16, MIPS_REG_17,
		MIPS_REG_18, MIPS_REG_19, MIPS_REG_20, MIPS_REG_21, MIPS_REG_22,
		MIPS_REG_23, MIPS_REG_24, MIPS_REG_25, MIPS_REG_26, MIPS_REG_27,
		MIPS_REG_28, MIPS_REG_29, MIPS_REG_30, MIPS_REG_31, MIPS_REG_FP,
		MIPS_REG_F0, MIPS_REG_F1, MIPS_REG_F2, MIPS_REG_F3, MIPS_REG_F4,
		MIPS_REG_F5, MIPS_REG_F6, MIPS_REG_F7, MIPS_REG_F8, MIPS_REG_F9,
		MIPS_REG_F10, MIPS_REG_F11, MIPS_REG_F12, MIPS_REG_F13, MIPS_REG_F14,
		MIPS_REG_F15, MIPS_REG_F16, MIPS_REG_F17, MIPS_REG_F18, MIPS_REG_F19,
		MIPS_REG_F20, MIPS_REG_F21, MIPS_REG_F22, MIPS_REG_F23, MIPS_REG_F24,
		MIPS_REG_F25, MIPS_REG_F26, MIPS_REG_F27, MIPS_REG_F28, MIPS_REG_F29,
		MIPS_REG_F30, MIPS_REG_F31, MIPS_REG_GP, MIPS_REG_AC0, MIPS_REG_AC1,
		MIPS_REG_AC2, MIPS_REG_AC3, MIPS_REG_0, MIPS_REG_1, MIPS_REG_2,
		MIPS_REG_3, MIPS_REG_4, MIPS_REG_5, MIPS_REG_6, MIPS_REG_7,
		MIPS_REG_8, MIPS_REG_9, MIPS_REG_10, MIPS_REG_11, MIPS_REG_12,
		MIPS_REG_13, MIPS_REG_14, MIPS_REG_15, MIPS_REG_16, MIPS_REG_17,
		MIPS_REG_18, MIPS_REG_19, MIPS_REG_20, MIPS_REG_21, MIPS_REG_22,
		MIPS_REG_23, MIPS_REG_24, MIPS_REG_25, MIPS_REG_26, MIPS_REG_27,
		MIPS_REG_28, MIPS_REG_29, MIPS_REG_30, MIPS_REG_31, MIPS_REG_K0,
		MIPS_REG_K1, MIPS_REG_AC0, MIPS_REG_AC1, MIPS_REG_AC2, MIPS_REG_AC3,
		MIPS_REG_MPL0, MIPS_REG_MPL1, MIPS_REG_MPL2, MIPS_REG_P0, MIPS_REG_P1,
		MIPS_REG_P2, MIPS_REG_RA, MIPS_REG_S0, MIPS_REG_S1, MIPS_REG_S2,
		MIPS_REG_S3, MIPS_REG_S4, MIPS_REG_S5, MIPS_REG_S6, MIPS_REG_S7,
		MIPS_REG_SP, MIPS_REG_T0, MIPS_REG_T1, MIPS_REG_T2, MIPS_REG_T3,
		MIPS_REG_T4, MIPS_REG_T5, MIPS_REG_T6, MIPS_REG_T7, MIPS_REG_T8,
		MIPS_REG_T9, MIPS_REG_V0, MIPS_REG_V1, MIPS_REG_W0, MIPS_REG_W1,
		MIPS_REG_W2, MIPS_REG_W3, MIPS_REG_W4, MIPS_REG_W5, MIPS_REG_W6,
		MIPS_REG_W7, MIPS_REG_W8, MIPS_REG_W9, MIPS_REG_W10, MIPS_REG_W11,
		MIPS_REG_W12, MIPS_REG_W13, MIPS_REG_W14, MIPS_REG_W15, MIPS_REG_W16,
		MIPS_REG_W17, MIPS_REG_W18, MIPS_REG_W19, MIPS_REG_W20, MIPS_REG_W21,
		MIPS_REG_W22, MIPS_REG_W23, MIPS_REG_W24, MIPS_REG_W25, MIPS_REG_W26,
		MIPS_REG_W27, MIPS_REG_W28, MIPS_REG_W29, MIPS_REG_W30, MIPS_REG_W31,
		MIPS_REG_ZERO, MIPS_REG_A0, MIPS_REG_A1, MIPS_REG_A2, MIPS_REG_A3,
		MIPS_REG_AC0, MIPS_REG_F0, MIPS_REG_F1, MIPS_REG_F2, MIPS_REG_F3,
		MIPS_REG_F4, MIPS_REG_F5, MIPS_REG_F6, MIPS_REG_F7, MIPS_REG_F8,
		MIPS_REG_F9, MIPS_REG_F10, MIPS_REG_F11, MIPS_REG_F12, MIPS_REG_F13,
		MIPS_REG_F14, MIPS_REG_F15, MIPS_REG_F16, MIPS_REG_F17, MIPS_REG_F18,
		MIPS_REG_F19, MIPS_REG_F20, MIPS_REG_F21, MIPS_REG_F22, MIPS_REG_F23,
		MIPS_REG_F24, MIPS_REG_F25, MIPS_REG_F26, MIPS_REG_F27, MIPS_REG_F28,
		MIPS_REG_F29, MIPS_REG_F30, MIPS_REG_F31, MIPS_REG_DSPOUTFLAG16_19, MIPS_REG_HI,
		MIPS_REG_K0, MIPS_REG_K1, MIPS_REG_LO, MIPS_REG_S0, MIPS_REG_S1,
		MIPS_REG_S2, MIPS_REG_S3, MIPS_REG_S4, MIPS_REG_S5, MIPS_REG_S6,
		MIPS_REG_S7, MIPS_REG_T0, MIPS_REG_T1, MIPS_REG_T2, MIPS_REG_T3,
		MIPS_REG_T4, MIPS_REG_T5, MIPS_REG_T6, MIPS_REG_T7, MIPS_REG_T8,
		MIPS_REG_T9, MIPS_REG_V0, MIPS_REG_V1,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif
