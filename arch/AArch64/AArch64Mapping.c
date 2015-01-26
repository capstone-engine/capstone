/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_ARM64

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "AArch64Mapping.h"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static name_map reg_name_maps[] = {
	{ ARM64_REG_INVALID, NULL },

	{ ARM64_REG_X29, "x29"},
	{ ARM64_REG_X30, "x30"},
	{ ARM64_REG_NZCV, "nzcv"},
	{ ARM64_REG_SP, "sp"},
	{ ARM64_REG_WSP, "wsp"},
	{ ARM64_REG_WZR, "wzr"},
	{ ARM64_REG_XZR, "xzr"},
	{ ARM64_REG_B0, "b0"},
	{ ARM64_REG_B1, "b1"},
	{ ARM64_REG_B2, "b2"},
	{ ARM64_REG_B3, "b3"},
	{ ARM64_REG_B4, "b4"},
	{ ARM64_REG_B5, "b5"},
	{ ARM64_REG_B6, "b6"},
	{ ARM64_REG_B7, "b7"},
	{ ARM64_REG_B8, "b8"},
	{ ARM64_REG_B9, "b9"},
	{ ARM64_REG_B10, "b10"},
	{ ARM64_REG_B11, "b11"},
	{ ARM64_REG_B12, "b12"},
	{ ARM64_REG_B13, "b13"},
	{ ARM64_REG_B14, "b14"},
	{ ARM64_REG_B15, "b15"},
	{ ARM64_REG_B16, "b16"},
	{ ARM64_REG_B17, "b17"},
	{ ARM64_REG_B18, "b18"},
	{ ARM64_REG_B19, "b19"},
	{ ARM64_REG_B20, "b20"},
	{ ARM64_REG_B21, "b21"},
	{ ARM64_REG_B22, "b22"},
	{ ARM64_REG_B23, "b23"},
	{ ARM64_REG_B24, "b24"},
	{ ARM64_REG_B25, "b25"},
	{ ARM64_REG_B26, "b26"},
	{ ARM64_REG_B27, "b27"},
	{ ARM64_REG_B28, "b28"},
	{ ARM64_REG_B29, "b29"},
	{ ARM64_REG_B30, "b30"},
	{ ARM64_REG_B31, "b31"},
	{ ARM64_REG_D0, "d0"},
	{ ARM64_REG_D1, "d1"},
	{ ARM64_REG_D2, "d2"},
	{ ARM64_REG_D3, "d3"},
	{ ARM64_REG_D4, "d4"},
	{ ARM64_REG_D5, "d5"},
	{ ARM64_REG_D6, "d6"},
	{ ARM64_REG_D7, "d7"},
	{ ARM64_REG_D8, "d8"},
	{ ARM64_REG_D9, "d9"},
	{ ARM64_REG_D10, "d10"},
	{ ARM64_REG_D11, "d11"},
	{ ARM64_REG_D12, "d12"},
	{ ARM64_REG_D13, "d13"},
	{ ARM64_REG_D14, "d14"},
	{ ARM64_REG_D15, "d15"},
	{ ARM64_REG_D16, "d16"},
	{ ARM64_REG_D17, "d17"},
	{ ARM64_REG_D18, "d18"},
	{ ARM64_REG_D19, "d19"},
	{ ARM64_REG_D20, "d20"},
	{ ARM64_REG_D21, "d21"},
	{ ARM64_REG_D22, "d22"},
	{ ARM64_REG_D23, "d23"},
	{ ARM64_REG_D24, "d24"},
	{ ARM64_REG_D25, "d25"},
	{ ARM64_REG_D26, "d26"},
	{ ARM64_REG_D27, "d27"},
	{ ARM64_REG_D28, "d28"},
	{ ARM64_REG_D29, "d29"},
	{ ARM64_REG_D30, "d30"},
	{ ARM64_REG_D31, "d31"},
	{ ARM64_REG_H0, "h0"},
	{ ARM64_REG_H1, "h1"},
	{ ARM64_REG_H2, "h2"},
	{ ARM64_REG_H3, "h3"},
	{ ARM64_REG_H4, "h4"},
	{ ARM64_REG_H5, "h5"},
	{ ARM64_REG_H6, "h6"},
	{ ARM64_REG_H7, "h7"},
	{ ARM64_REG_H8, "h8"},
	{ ARM64_REG_H9, "h9"},
	{ ARM64_REG_H10, "h10"},
	{ ARM64_REG_H11, "h11"},
	{ ARM64_REG_H12, "h12"},
	{ ARM64_REG_H13, "h13"},
	{ ARM64_REG_H14, "h14"},
	{ ARM64_REG_H15, "h15"},
	{ ARM64_REG_H16, "h16"},
	{ ARM64_REG_H17, "h17"},
	{ ARM64_REG_H18, "h18"},
	{ ARM64_REG_H19, "h19"},
	{ ARM64_REG_H20, "h20"},
	{ ARM64_REG_H21, "h21"},
	{ ARM64_REG_H22, "h22"},
	{ ARM64_REG_H23, "h23"},
	{ ARM64_REG_H24, "h24"},
	{ ARM64_REG_H25, "h25"},
	{ ARM64_REG_H26, "h26"},
	{ ARM64_REG_H27, "h27"},
	{ ARM64_REG_H28, "h28"},
	{ ARM64_REG_H29, "h29"},
	{ ARM64_REG_H30, "h30"},
	{ ARM64_REG_H31, "h31"},
	{ ARM64_REG_Q0, "q0"},
	{ ARM64_REG_Q1, "q1"},
	{ ARM64_REG_Q2, "q2"},
	{ ARM64_REG_Q3, "q3"},
	{ ARM64_REG_Q4, "q4"},
	{ ARM64_REG_Q5, "q5"},
	{ ARM64_REG_Q6, "q6"},
	{ ARM64_REG_Q7, "q7"},
	{ ARM64_REG_Q8, "q8"},
	{ ARM64_REG_Q9, "q9"},
	{ ARM64_REG_Q10, "q10"},
	{ ARM64_REG_Q11, "q11"},
	{ ARM64_REG_Q12, "q12"},
	{ ARM64_REG_Q13, "q13"},
	{ ARM64_REG_Q14, "q14"},
	{ ARM64_REG_Q15, "q15"},
	{ ARM64_REG_Q16, "q16"},
	{ ARM64_REG_Q17, "q17"},
	{ ARM64_REG_Q18, "q18"},
	{ ARM64_REG_Q19, "q19"},
	{ ARM64_REG_Q20, "q20"},
	{ ARM64_REG_Q21, "q21"},
	{ ARM64_REG_Q22, "q22"},
	{ ARM64_REG_Q23, "q23"},
	{ ARM64_REG_Q24, "q24"},
	{ ARM64_REG_Q25, "q25"},
	{ ARM64_REG_Q26, "q26"},
	{ ARM64_REG_Q27, "q27"},
	{ ARM64_REG_Q28, "q28"},
	{ ARM64_REG_Q29, "q29"},
	{ ARM64_REG_Q30, "q30"},
	{ ARM64_REG_Q31, "q31"},
	{ ARM64_REG_S0, "s0"},
	{ ARM64_REG_S1, "s1"},
	{ ARM64_REG_S2, "s2"},
	{ ARM64_REG_S3, "s3"},
	{ ARM64_REG_S4, "s4"},
	{ ARM64_REG_S5, "s5"},
	{ ARM64_REG_S6, "s6"},
	{ ARM64_REG_S7, "s7"},
	{ ARM64_REG_S8, "s8"},
	{ ARM64_REG_S9, "s9"},
	{ ARM64_REG_S10, "s10"},
	{ ARM64_REG_S11, "s11"},
	{ ARM64_REG_S12, "s12"},
	{ ARM64_REG_S13, "s13"},
	{ ARM64_REG_S14, "s14"},
	{ ARM64_REG_S15, "s15"},
	{ ARM64_REG_S16, "s16"},
	{ ARM64_REG_S17, "s17"},
	{ ARM64_REG_S18, "s18"},
	{ ARM64_REG_S19, "s19"},
	{ ARM64_REG_S20, "s20"},
	{ ARM64_REG_S21, "s21"},
	{ ARM64_REG_S22, "s22"},
	{ ARM64_REG_S23, "s23"},
	{ ARM64_REG_S24, "s24"},
	{ ARM64_REG_S25, "s25"},
	{ ARM64_REG_S26, "s26"},
	{ ARM64_REG_S27, "s27"},
	{ ARM64_REG_S28, "s28"},
	{ ARM64_REG_S29, "s29"},
	{ ARM64_REG_S30, "s30"},
	{ ARM64_REG_S31, "s31"},
	{ ARM64_REG_W0, "w0"},
	{ ARM64_REG_W1, "w1"},
	{ ARM64_REG_W2, "w2"},
	{ ARM64_REG_W3, "w3"},
	{ ARM64_REG_W4, "w4"},
	{ ARM64_REG_W5, "w5"},
	{ ARM64_REG_W6, "w6"},
	{ ARM64_REG_W7, "w7"},
	{ ARM64_REG_W8, "w8"},
	{ ARM64_REG_W9, "w9"},
	{ ARM64_REG_W10, "w10"},
	{ ARM64_REG_W11, "w11"},
	{ ARM64_REG_W12, "w12"},
	{ ARM64_REG_W13, "w13"},
	{ ARM64_REG_W14, "w14"},
	{ ARM64_REG_W15, "w15"},
	{ ARM64_REG_W16, "w16"},
	{ ARM64_REG_W17, "w17"},
	{ ARM64_REG_W18, "w18"},
	{ ARM64_REG_W19, "w19"},
	{ ARM64_REG_W20, "w20"},
	{ ARM64_REG_W21, "w21"},
	{ ARM64_REG_W22, "w22"},
	{ ARM64_REG_W23, "w23"},
	{ ARM64_REG_W24, "w24"},
	{ ARM64_REG_W25, "w25"},
	{ ARM64_REG_W26, "w26"},
	{ ARM64_REG_W27, "w27"},
	{ ARM64_REG_W28, "w28"},
	{ ARM64_REG_W29, "w29"},
	{ ARM64_REG_W30, "w30"},
	{ ARM64_REG_X0, "x0"},
	{ ARM64_REG_X1, "x1"},
	{ ARM64_REG_X2, "x2"},
	{ ARM64_REG_X3, "x3"},
	{ ARM64_REG_X4, "x4"},
	{ ARM64_REG_X5, "x5"},
	{ ARM64_REG_X6, "x6"},
	{ ARM64_REG_X7, "x7"},
	{ ARM64_REG_X8, "x8"},
	{ ARM64_REG_X9, "x9"},
	{ ARM64_REG_X10, "x10"},
	{ ARM64_REG_X11, "x11"},
	{ ARM64_REG_X12, "x12"},
	{ ARM64_REG_X13, "x13"},
	{ ARM64_REG_X14, "x14"},
	{ ARM64_REG_X15, "x15"},
	{ ARM64_REG_X16, "x16"},
	{ ARM64_REG_X17, "x17"},
	{ ARM64_REG_X18, "x18"},
	{ ARM64_REG_X19, "x19"},
	{ ARM64_REG_X20, "x20"},
	{ ARM64_REG_X21, "x21"},
	{ ARM64_REG_X22, "x22"},
	{ ARM64_REG_X23, "x23"},
	{ ARM64_REG_X24, "x24"},
	{ ARM64_REG_X25, "x25"},
	{ ARM64_REG_X26, "x26"},
	{ ARM64_REG_X27, "x27"},
	{ ARM64_REG_X28, "x28"},

	{ ARM64_REG_V0, "v0"},
	{ ARM64_REG_V1, "v1"},
	{ ARM64_REG_V2, "v2"},
	{ ARM64_REG_V3, "v3"},
	{ ARM64_REG_V4, "v4"},
	{ ARM64_REG_V5, "v5"},
	{ ARM64_REG_V6, "v6"},
	{ ARM64_REG_V7, "v7"},
	{ ARM64_REG_V8, "v8"},
	{ ARM64_REG_V9, "v9"},
	{ ARM64_REG_V10, "v10"},
	{ ARM64_REG_V11, "v11"},
	{ ARM64_REG_V12, "v12"},
	{ ARM64_REG_V13, "v13"},
	{ ARM64_REG_V14, "v14"},
	{ ARM64_REG_V15, "v15"},
	{ ARM64_REG_V16, "v16"},
	{ ARM64_REG_V17, "v17"},
	{ ARM64_REG_V18, "v18"},
	{ ARM64_REG_V19, "v19"},
	{ ARM64_REG_V20, "v20"},
	{ ARM64_REG_V21, "v21"},
	{ ARM64_REG_V22, "v22"},
	{ ARM64_REG_V23, "v23"},
	{ ARM64_REG_V24, "v24"},
	{ ARM64_REG_V25, "v25"},
	{ ARM64_REG_V26, "v26"},
	{ ARM64_REG_V27, "v27"},
	{ ARM64_REG_V28, "v28"},
	{ ARM64_REG_V29, "v29"},
	{ ARM64_REG_V30, "v30"},
	{ ARM64_REG_V31, "v31"},
};
#endif

const char *AArch64_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= ARM64_REG_ENDING)
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
		AArch64_ABSv16i8, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv1i64, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv2i32, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv2i64, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv4i16, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv4i32, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv8i16, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ABSv8i8, ARM64_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADCSWr, ARM64_INS_ADC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADCSXr, ARM64_INS_ADC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADCWr, ARM64_INS_ADC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADCXr, ARM64_INS_ADC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv2i64_v2i32, ARM64_INS_ADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv2i64_v4i32, ARM64_INS_ADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv4i32_v4i16, ARM64_INS_ADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv4i32_v8i16, ARM64_INS_ADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv8i16_v16i8, ARM64_INS_ADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDHNv8i16_v8i8, ARM64_INS_ADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv16i8, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv2i32, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv2i64, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv2i64p, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv4i16, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv4i32, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv8i16, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDPv8i8, ARM64_INS_ADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSWri, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSWrs, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSWrx, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSXri, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSXrs, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSXrx, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDSXrx64, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDVv16i8v, ARM64_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDVv4i16v, ARM64_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDVv4i32v, ARM64_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDVv8i16v, ARM64_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDVv8i8v, ARM64_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDWri, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDWrs, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDWrx, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDXri, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDXrs, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDXrx, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDXrx64, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv16i8, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv1i64, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv2i32, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv2i64, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv4i16, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv4i32, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv8i16, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADDv8i8, ARM64_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ADR, ARM64_INS_ADR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ADRP, ARM64_INS_ADRP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_AESDrr, ARM64_INS_AESD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_AESErr, ARM64_INS_AESE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_AESIMCrr, ARM64_INS_AESIMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_AESMCrr, ARM64_INS_AESMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDSWri, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDSWrs, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDSXri, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDSXrs, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDWri, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDWrs, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDXri, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDXrs, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDv16i8, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ANDv8i8, ARM64_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ASRVWr, ARM64_INS_ASR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ASRVXr, ARM64_INS_ASR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_B, ARM64_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_BFMWri, ARM64_INS_BFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BFMXri, ARM64_INS_BFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BICSWrs, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BICSXrs, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BICWrs, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BICXrs, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv16i8, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv2i32, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv4i16, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv4i32, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv8i16, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BICv8i8, ARM64_INS_BIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BIFv16i8, ARM64_INS_BIF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BIFv8i8, ARM64_INS_BIF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BITv16i8, ARM64_INS_BIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BITv8i8, ARM64_INS_BIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BL, ARM64_INS_BL,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BLR, ARM64_INS_BLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BR, ARM64_INS_BR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		AArch64_BRK, ARM64_INS_BRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_BSLv16i8, ARM64_INS_BSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_BSLv8i8, ARM64_INS_BSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_Bcc, ARM64_INS_B,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_CBNZW, ARM64_INS_CBNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_CBNZX, ARM64_INS_CBNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_CBZW, ARM64_INS_CBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_CBZX, ARM64_INS_CBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_CCMNWi, ARM64_INS_CCMN,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMNWr, ARM64_INS_CCMN,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMNXi, ARM64_INS_CCMN,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMNXr, ARM64_INS_CCMN,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMPWi, ARM64_INS_CCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMPWr, ARM64_INS_CCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMPXi, ARM64_INS_CCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CCMPXr, ARM64_INS_CCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLREX, ARM64_INS_CLREX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSWr, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSXr, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv16i8, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv2i32, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv4i16, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv4i32, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv8i16, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLSv8i8, ARM64_INS_CLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZWr, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZXr, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv16i8, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv2i32, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv4i16, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv4i32, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv8i16, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CLZv8i8, ARM64_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv16i8, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv16i8rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv1i64, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv1i64rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv2i32, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv2i32rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv2i64, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv2i64rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv4i16, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv4i16rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv4i32, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv4i32rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv8i16, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv8i16rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv8i8, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMEQv8i8rz, ARM64_INS_CMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv16i8, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv16i8rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv1i64, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv1i64rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv2i32, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv2i32rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv2i64, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv2i64rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv4i16, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv4i16rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv4i32, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv4i32rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv8i16, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv8i16rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv8i8, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGEv8i8rz, ARM64_INS_CMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv16i8, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv16i8rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv1i64, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv1i64rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv2i32, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv2i32rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv2i64, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv2i64rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv4i16, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv4i16rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv4i32, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv4i32rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv8i16, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv8i16rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv8i8, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMGTv8i8rz, ARM64_INS_CMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv16i8, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv1i64, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv2i32, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv2i64, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv4i16, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv4i32, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv8i16, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHIv8i8, ARM64_INS_CMHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv16i8, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv1i64, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv2i32, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv2i64, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv4i16, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv4i32, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv8i16, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMHSv8i8, ARM64_INS_CMHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv16i8rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv1i64rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv2i32rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv2i64rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv4i16rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv4i32rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv8i16rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLEv8i8rz, ARM64_INS_CMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv16i8rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv1i64rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv2i32rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv2i64rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv4i16rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv4i32rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv8i16rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMLTv8i8rz, ARM64_INS_CMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv16i8, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv1i64, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv2i32, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv2i64, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv4i16, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv4i32, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv8i16, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CMTSTv8i8, ARM64_INS_CMTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CNTv16i8, ARM64_INS_CNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CNTv8i8, ARM64_INS_CNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CPYi16, ARM64_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CPYi32, ARM64_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CPYi64, ARM64_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CPYi8, ARM64_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32Brr, ARM64_INS_CRC32B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32CBrr, ARM64_INS_CRC32CB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32CHrr, ARM64_INS_CRC32CH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32CWrr, ARM64_INS_CRC32CW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32CXrr, ARM64_INS_CRC32CX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32Hrr, ARM64_INS_CRC32H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32Wrr, ARM64_INS_CRC32W,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CRC32Xrr, ARM64_INS_CRC32X,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRC, 0 }, 0, 0
#endif
	},
	{
		AArch64_CSELWr, ARM64_INS_CSEL,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSELXr, ARM64_INS_CSEL,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSINCWr, ARM64_INS_CSINC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSINCXr, ARM64_INS_CSINC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSINVWr, ARM64_INS_CSINV,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSINVXr, ARM64_INS_CSINV,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSNEGWr, ARM64_INS_CSNEG,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_CSNEGXr, ARM64_INS_CSNEG,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DCPS1, ARM64_INS_DCPS1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DCPS2, ARM64_INS_DCPS2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DCPS3, ARM64_INS_DCPS3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DMB, ARM64_INS_DMB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DRPS, ARM64_INS_DRPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DSB, ARM64_INS_DSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv16i8gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv16i8lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv2i32gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv2i32lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv2i64gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv2i64lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv4i16gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv4i16lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv4i32gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv4i32lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv8i16gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv8i16lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv8i8gpr, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_DUPv8i8lane, ARM64_INS_DUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_EONWrs, ARM64_INS_EON,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EONXrs, ARM64_INS_EON,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EORWri, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EORWrs, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EORXri, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EORXrs, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EORv16i8, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_EORv8i8, ARM64_INS_EOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ERET, ARM64_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EXTRWrri, ARM64_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EXTRXrri, ARM64_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_EXTv16i8, ARM64_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_EXTv8i8, ARM64_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABD32, ARM64_INS_FABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABD64, ARM64_INS_FABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABDv2f32, ARM64_INS_FABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABDv2f64, ARM64_INS_FABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABDv4f32, ARM64_INS_FABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABSDr, ARM64_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABSSr, ARM64_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABSv2f32, ARM64_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABSv2f64, ARM64_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FABSv4f32, ARM64_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGE32, ARM64_INS_FACGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGE64, ARM64_INS_FACGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGEv2f32, ARM64_INS_FACGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGEv2f64, ARM64_INS_FACGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGEv4f32, ARM64_INS_FACGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGT32, ARM64_INS_FACGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGT64, ARM64_INS_FACGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGTv2f32, ARM64_INS_FACGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGTv2f64, ARM64_INS_FACGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FACGTv4f32, ARM64_INS_FACGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDDrr, ARM64_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDPv2f32, ARM64_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDPv2f64, ARM64_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDPv2i32p, ARM64_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDPv2i64p, ARM64_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDPv4f32, ARM64_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDSrr, ARM64_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDv2f32, ARM64_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDv2f64, ARM64_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FADDv4f32, ARM64_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCCMPDrr, ARM64_INS_FCCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCCMPEDrr, ARM64_INS_FCCMPE,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCCMPESrr, ARM64_INS_FCCMPE,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCCMPSrr, ARM64_INS_FCCMP,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQ32, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQ64, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv1i32rz, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv1i64rz, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv2f32, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv2f64, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv2i32rz, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv2i64rz, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv4f32, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMEQv4i32rz, ARM64_INS_FCMEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGE32, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGE64, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv1i32rz, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv1i64rz, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv2f32, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv2f64, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv2i32rz, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv2i64rz, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv4f32, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGEv4i32rz, ARM64_INS_FCMGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGT32, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGT64, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv1i32rz, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv1i64rz, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv2f32, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv2f64, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv2i32rz, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv2i64rz, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv4f32, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMGTv4i32rz, ARM64_INS_FCMGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLEv1i32rz, ARM64_INS_FCMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLEv1i64rz, ARM64_INS_FCMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLEv2i32rz, ARM64_INS_FCMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLEv2i64rz, ARM64_INS_FCMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLEv4i32rz, ARM64_INS_FCMLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLTv1i32rz, ARM64_INS_FCMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLTv1i64rz, ARM64_INS_FCMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLTv2i32rz, ARM64_INS_FCMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLTv2i64rz, ARM64_INS_FCMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMLTv4i32rz, ARM64_INS_FCMLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPDri, ARM64_INS_FCMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPDrr, ARM64_INS_FCMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPEDri, ARM64_INS_FCMPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPEDrr, ARM64_INS_FCMPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPESri, ARM64_INS_FCMPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPESrr, ARM64_INS_FCMPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPSri, ARM64_INS_FCMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCMPSrr, ARM64_INS_FCMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCSELDrrr, ARM64_INS_FCSEL,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCSELSrrr, ARM64_INS_FCSEL,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASUWDr, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASUWSr, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASUXDr, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASUXSr, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASv1i32, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASv1i64, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASv2f32, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASv2f64, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTASv4f32, ARM64_INS_FCVTAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUUWDr, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUUWSr, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUUXDr, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUUXSr, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUv1i32, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUv1i64, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUv2f32, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUv2f64, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTAUv4f32, ARM64_INS_FCVTAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTDHr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTDSr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTHDr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTHSr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTLv2i32, ARM64_INS_FCVTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTLv4i16, ARM64_INS_FCVTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTLv4i32, ARM64_INS_FCVTL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTLv8i16, ARM64_INS_FCVTL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSUWDr, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSUWSr, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSUXDr, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSUXSr, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSv1i32, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSv1i64, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSv2f32, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSv2f64, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMSv4f32, ARM64_INS_FCVTMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUUWDr, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUUWSr, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUUXDr, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUUXSr, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUv1i32, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUv1i64, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUv2f32, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUv2f64, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTMUv4f32, ARM64_INS_FCVTMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSUWDr, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSUWSr, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSUXDr, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSUXSr, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSv1i32, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSv1i64, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSv2f32, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSv2f64, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNSv4f32, ARM64_INS_FCVTNS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUUWDr, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUUWSr, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUUXDr, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUUXSr, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUv1i32, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUv1i64, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUv2f32, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUv2f64, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNUv4f32, ARM64_INS_FCVTNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNv2i32, ARM64_INS_FCVTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNv4i16, ARM64_INS_FCVTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNv4i32, ARM64_INS_FCVTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTNv8i16, ARM64_INS_FCVTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSUWDr, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSUWSr, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSUXDr, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSUXSr, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSv1i32, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSv1i64, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSv2f32, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSv2f64, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPSv4f32, ARM64_INS_FCVTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUUWDr, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUUWSr, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUUXDr, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUUXSr, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUv1i32, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUv1i64, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUv2f32, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUv2f64, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTPUv4f32, ARM64_INS_FCVTPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTSDr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTSHr, ARM64_INS_FCVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTXNv1i64, ARM64_INS_FCVTXN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTXNv2f32, ARM64_INS_FCVTXN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTXNv4f32, ARM64_INS_FCVTXN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSSWDri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSSWSri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSSXDri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSSXSri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSUWDr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSUWSr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSUXDr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSUXSr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntSWDri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntSWSri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntSXDri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntSXSri, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntUWDr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntUWSr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntUXDr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_IntUXSr, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_Intv2f32, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_Intv2f64, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZS_Intv4f32, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSd, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSs, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv1i32, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv1i64, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv2f32, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv2f64, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv2i32_shift, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv2i64_shift, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv4f32, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZSv4i32_shift, ARM64_INS_FCVTZS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUSWDri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUSWSri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUSXDri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUSXSri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUUWDr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUUWSr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUUXDr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUUXSr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntSWDri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntSWSri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntSXDri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntSXSri, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntUWDr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntUWSr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntUXDr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_IntUXSr, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_Intv2f32, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_Intv2f64, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZU_Intv4f32, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUd, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUs, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv1i32, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv1i64, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv2f32, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv2f64, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv2i32_shift, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv2i64_shift, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv4f32, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FCVTZUv4i32_shift, ARM64_INS_FCVTZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FDIVDrr, ARM64_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FDIVSrr, ARM64_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FDIVv2f32, ARM64_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FDIVv2f64, ARM64_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FDIVv4f32, ARM64_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMADDDrrr, ARM64_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMADDSrrr, ARM64_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXDrr, ARM64_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMDrr, ARM64_INS_FMAXNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMPv2f32, ARM64_INS_FMAXNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMPv2f64, ARM64_INS_FMAXNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMPv2i32p, ARM64_INS_FMAXNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMPv2i64p, ARM64_INS_FMAXNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMPv4f32, ARM64_INS_FMAXNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMSrr, ARM64_INS_FMAXNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMVv4i32v, ARM64_INS_FMAXNMV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMv2f32, ARM64_INS_FMAXNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMv2f64, ARM64_INS_FMAXNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXNMv4f32, ARM64_INS_FMAXNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXPv2f32, ARM64_INS_FMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXPv2f64, ARM64_INS_FMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXPv2i32p, ARM64_INS_FMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXPv2i64p, ARM64_INS_FMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXPv4f32, ARM64_INS_FMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXSrr, ARM64_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXVv4i32v, ARM64_INS_FMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXv2f32, ARM64_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXv2f64, ARM64_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMAXv4f32, ARM64_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINDrr, ARM64_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMDrr, ARM64_INS_FMINNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMPv2f32, ARM64_INS_FMINNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMPv2f64, ARM64_INS_FMINNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMPv2i32p, ARM64_INS_FMINNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMPv2i64p, ARM64_INS_FMINNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMPv4f32, ARM64_INS_FMINNMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMSrr, ARM64_INS_FMINNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMVv4i32v, ARM64_INS_FMINNMV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMv2f32, ARM64_INS_FMINNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMv2f64, ARM64_INS_FMINNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINNMv4f32, ARM64_INS_FMINNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINPv2f32, ARM64_INS_FMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINPv2f64, ARM64_INS_FMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINPv2i32p, ARM64_INS_FMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINPv2i64p, ARM64_INS_FMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINPv4f32, ARM64_INS_FMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINSrr, ARM64_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINVv4i32v, ARM64_INS_FMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINv2f32, ARM64_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINv2f64, ARM64_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMINv4f32, ARM64_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv1i32_indexed, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv1i64_indexed, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv2f32, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv2f64, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv2i32_indexed, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv2i64_indexed, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv4f32, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLAv4i32_indexed, ARM64_INS_FMLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv1i32_indexed, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv1i64_indexed, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv2f32, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv2f64, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv2i32_indexed, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv2i64_indexed, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv4f32, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMLSv4i32_indexed, ARM64_INS_FMLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVDXHighr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVDXr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVDi, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVDr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVSWr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVSi, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVSr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVWSr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVXDHighr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVXDr, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVv2f32_ns, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVv2f64_ns, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMOVv4f32_ns, ARM64_INS_FMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMSUBDrrr, ARM64_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMSUBSrrr, ARM64_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULDrr, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULSrr, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULX32, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULX64, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv1i32_indexed, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv1i64_indexed, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv2f32, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv2f64, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv2i32_indexed, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv2i64_indexed, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv4f32, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULXv4i32_indexed, ARM64_INS_FMULX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv1i32_indexed, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv1i64_indexed, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv2f32, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv2f64, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv2i32_indexed, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv2i64_indexed, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv4f32, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FMULv4i32_indexed, ARM64_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNEGDr, ARM64_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNEGSr, ARM64_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNEGv2f32, ARM64_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNEGv2f64, ARM64_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNEGv4f32, ARM64_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMADDDrrr, ARM64_INS_FNMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMADDSrrr, ARM64_INS_FNMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMSUBDrrr, ARM64_INS_FNMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMSUBSrrr, ARM64_INS_FNMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMULDrr, ARM64_INS_FNMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FNMULSrr, ARM64_INS_FNMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPEv1i32, ARM64_INS_FRECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPEv1i64, ARM64_INS_FRECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPEv2f32, ARM64_INS_FRECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPEv2f64, ARM64_INS_FRECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPEv4f32, ARM64_INS_FRECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPS32, ARM64_INS_FRECPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPS64, ARM64_INS_FRECPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPSv2f32, ARM64_INS_FRECPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPSv2f64, ARM64_INS_FRECPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPSv4f32, ARM64_INS_FRECPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPXv1i32, ARM64_INS_FRECPX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRECPXv1i64, ARM64_INS_FRECPX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTADr, ARM64_INS_FRINTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTASr, ARM64_INS_FRINTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTAv2f32, ARM64_INS_FRINTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTAv2f64, ARM64_INS_FRINTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTAv4f32, ARM64_INS_FRINTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTIDr, ARM64_INS_FRINTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTISr, ARM64_INS_FRINTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTIv2f32, ARM64_INS_FRINTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTIv2f64, ARM64_INS_FRINTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTIv4f32, ARM64_INS_FRINTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTMDr, ARM64_INS_FRINTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTMSr, ARM64_INS_FRINTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTMv2f32, ARM64_INS_FRINTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTMv2f64, ARM64_INS_FRINTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTMv4f32, ARM64_INS_FRINTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTNDr, ARM64_INS_FRINTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTNSr, ARM64_INS_FRINTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTNv2f32, ARM64_INS_FRINTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTNv2f64, ARM64_INS_FRINTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTNv4f32, ARM64_INS_FRINTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTPDr, ARM64_INS_FRINTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTPSr, ARM64_INS_FRINTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTPv2f32, ARM64_INS_FRINTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTPv2f64, ARM64_INS_FRINTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTPv4f32, ARM64_INS_FRINTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTXDr, ARM64_INS_FRINTX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTXSr, ARM64_INS_FRINTX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTXv2f32, ARM64_INS_FRINTX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTXv2f64, ARM64_INS_FRINTX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTXv4f32, ARM64_INS_FRINTX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTZDr, ARM64_INS_FRINTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTZSr, ARM64_INS_FRINTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTZv2f32, ARM64_INS_FRINTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTZv2f64, ARM64_INS_FRINTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRINTZv4f32, ARM64_INS_FRINTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTEv1i32, ARM64_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTEv1i64, ARM64_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTEv2f32, ARM64_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTEv2f64, ARM64_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTEv4f32, ARM64_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTS32, ARM64_INS_FRSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTS64, ARM64_INS_FRSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTSv2f32, ARM64_INS_FRSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTSv2f64, ARM64_INS_FRSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FRSQRTSv4f32, ARM64_INS_FRSQRTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSQRTDr, ARM64_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSQRTSr, ARM64_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSQRTv2f32, ARM64_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSQRTv2f64, ARM64_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSQRTv4f32, ARM64_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSUBDrr, ARM64_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSUBSrr, ARM64_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSUBv2f32, ARM64_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSUBv2f64, ARM64_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_FSUBv4f32, ARM64_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_HINT, ARM64_INS_HINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_HLT, ARM64_INS_HLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_HVC, ARM64_INS_HVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi16gpr, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi16lane, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi32gpr, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi32lane, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi64gpr, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi64lane, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi8gpr, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_INSvi8lane, ARM64_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ISB, ARM64_INS_ISB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv16b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv16b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv1d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv1d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv2d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv2d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv2s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv2s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv4h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv4h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv4s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv4s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv8b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv8b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv8h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Fourv8h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev16b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev16b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev1d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev1d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev2d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev2d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev2s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev2s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev4h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev4h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev4s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev4s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev8b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev8b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev8h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Onev8h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv16b, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv16b_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv1d, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv1d_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv2d, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv2d_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv2s, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv2s_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv4h, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv4h_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv4s, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv4s_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv8b, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv8b_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv8h, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Rv8h_POST, ARM64_INS_LD1R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev16b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev16b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev1d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev1d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev2d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev2d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev2s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev2s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev4h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev4h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev4s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev4s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev8b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev8b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev8h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Threev8h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov16b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov16b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov1d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov1d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov2d, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov2d_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov2s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov2s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov4h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov4h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov4s, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov4s_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov8b, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov8b_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov8h, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1Twov8h_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i16, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i16_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i32, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i32_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i64, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i64_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i8, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD1i8_POST, ARM64_INS_LD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv16b, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv16b_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv1d, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv1d_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv2d, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv2d_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv2s, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv2s_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv4h, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv4h_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv4s, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv4s_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv8b, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv8b_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv8h, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Rv8h_POST, ARM64_INS_LD2R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov16b, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov16b_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov2d, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov2d_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov2s, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov2s_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov4h, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov4h_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov4s, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov4s_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov8b, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov8b_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov8h, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2Twov8h_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i16, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i16_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i32, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i32_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i64, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i64_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i8, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD2i8_POST, ARM64_INS_LD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv16b, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv16b_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv1d, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv1d_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv2d, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv2d_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv2s, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv2s_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv4h, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv4h_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv4s, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv4s_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv8b, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv8b_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv8h, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Rv8h_POST, ARM64_INS_LD3R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev16b, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev16b_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev2d, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev2d_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev2s, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev2s_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev4h, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev4h_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev4s, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev4s_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev8b, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev8b_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev8h, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3Threev8h_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i16, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i16_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i32, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i32_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i64, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i64_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i8, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD3i8_POST, ARM64_INS_LD3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv16b, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv16b_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv2d, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv2d_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv2s, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv2s_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv4h, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv4h_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv4s, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv4s_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv8b, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv8b_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv8h, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Fourv8h_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv16b, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv16b_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv1d, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv1d_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv2d, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv2d_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv2s, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv2s_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv4h, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv4h_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv4s, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv4s_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv8b, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv8b_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv8h, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4Rv8h_POST, ARM64_INS_LD4R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i16, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i16_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i32, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i32_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i64, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i64_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i8, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LD4i8_POST, ARM64_INS_LD4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_LDARB, ARM64_INS_LDARB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDARH, ARM64_INS_LDARH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDARW, ARM64_INS_LDAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDARX, ARM64_INS_LDAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXPW, ARM64_INS_LDAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXPX, ARM64_INS_LDAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXRB, ARM64_INS_LDAXRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXRH, ARM64_INS_LDAXRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXRW, ARM64_INS_LDAXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDAXRX, ARM64_INS_LDAXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDNPDi, ARM64_INS_LDNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDNPQi, ARM64_INS_LDNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDNPSi, ARM64_INS_LDNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDNPWi, ARM64_INS_LDNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDNPXi, ARM64_INS_LDNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPDi, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPDpost, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPDpre, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPQi, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPQpost, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPQpre, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSWi, ARM64_INS_LDPSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSWpost, ARM64_INS_LDPSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSWpre, ARM64_INS_LDPSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSi, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSpost, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPSpre, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPWi, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPWpost, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPWpre, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPXi, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPXpost, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDPXpre, ARM64_INS_LDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBBpost, ARM64_INS_LDRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBBpre, ARM64_INS_LDRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBBroW, ARM64_INS_LDRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBBroX, ARM64_INS_LDRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBBui, ARM64_INS_LDRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRBui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDl, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRDui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHHpost, ARM64_INS_LDRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHHpre, ARM64_INS_LDRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHHroW, ARM64_INS_LDRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHHroX, ARM64_INS_LDRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHHui, ARM64_INS_LDRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRHui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQl, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRQui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBWpost, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBWpre, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBWroW, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBWroX, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBWui, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBXpost, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBXpre, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBXroW, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBXroX, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSBXui, ARM64_INS_LDRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHWpost, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHWpre, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHWroW, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHWroX, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHWui, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHXpost, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHXpre, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHXroW, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHXroX, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSHXui, ARM64_INS_LDRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWl, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWpost, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWpre, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWroW, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWroX, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSWui, ARM64_INS_LDRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSl, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRSui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWl, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRWui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXl, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXpost, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXpre, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXroW, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXroX, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDRXui, ARM64_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRBi, ARM64_INS_LDTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRHi, ARM64_INS_LDTRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRSBWi, ARM64_INS_LDTRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRSBXi, ARM64_INS_LDTRSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRSHWi, ARM64_INS_LDTRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRSHXi, ARM64_INS_LDTRSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRSWi, ARM64_INS_LDTRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRWi, ARM64_INS_LDTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDTRXi, ARM64_INS_LDTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURBBi, ARM64_INS_LDURB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURBi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURDi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURHHi, ARM64_INS_LDURH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURHi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURQi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSBWi, ARM64_INS_LDURSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSBXi, ARM64_INS_LDURSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSHWi, ARM64_INS_LDURSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSHXi, ARM64_INS_LDURSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSWi, ARM64_INS_LDURSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURSi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURWi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDURXi, ARM64_INS_LDUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXPW, ARM64_INS_LDXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXPX, ARM64_INS_LDXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXRB, ARM64_INS_LDXRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXRH, ARM64_INS_LDXRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXRW, ARM64_INS_LDXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LDXRX, ARM64_INS_LDXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LSLVWr, ARM64_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LSLVXr, ARM64_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LSRVWr, ARM64_INS_LSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_LSRVXr, ARM64_INS_LSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MADDWrrr, ARM64_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MADDXrrr, ARM64_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv16i8, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv2i32, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv2i32_indexed, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv4i16, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv4i16_indexed, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv4i32, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv4i32_indexed, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv8i16, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv8i16_indexed, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLAv8i8, ARM64_INS_MLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv16i8, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv2i32, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv2i32_indexed, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv4i16, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv4i16_indexed, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv4i32, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv4i32_indexed, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv8i16, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv8i16_indexed, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MLSv8i8, ARM64_INS_MLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVID, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv16b_ns, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv2d_ns, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv2i32, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv2s_msl, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv4i16, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv4i32, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv4s_msl, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv8b_ns, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVIv8i16, ARM64_INS_MOVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVKWi, ARM64_INS_MOVK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVKXi, ARM64_INS_MOVK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVNWi, ARM64_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVNXi, ARM64_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVZWi, ARM64_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MOVZXi, ARM64_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MRS, ARM64_INS_MRS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MSR, ARM64_INS_MSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MSRpstate, ARM64_INS_MSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MSUBWrrr, ARM64_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MSUBXrrr, ARM64_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv16i8, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv2i32, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv2i32_indexed, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv4i16, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv4i16_indexed, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv4i32, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv4i32_indexed, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv8i16, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv8i16_indexed, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MULv8i8, ARM64_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv2i32, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv2s_msl, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv4i16, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv4i32, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv4s_msl, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_MVNIv8i16, ARM64_INS_MVNI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv16i8, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv1i64, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv2i32, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv2i64, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv4i16, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv4i32, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv8i16, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NEGv8i8, ARM64_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NOTv16i8, ARM64_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_NOTv8i8, ARM64_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORNWrs, ARM64_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORNXrs, ARM64_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORNv16i8, ARM64_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORNv8i8, ARM64_INS_ORN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRWri, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRWrs, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRXri, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRXrs, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv16i8, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv2i32, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv4i16, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv4i32, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv8i16, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ORRv8i8, ARM64_INS_ORR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULLv16i8, ARM64_INS_PMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULLv1i64, ARM64_INS_PMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULLv2i64, ARM64_INS_PMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULLv8i8, ARM64_INS_PMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULv16i8, ARM64_INS_PMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_PMULv8i8, ARM64_INS_PMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_PRFMl, ARM64_INS_PRFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_PRFMroW, ARM64_INS_PRFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_PRFMroX, ARM64_INS_PRFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_PRFMui, ARM64_INS_PRFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_PRFUMi, ARM64_INS_PRFUM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv2i64_v2i32, ARM64_INS_RADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv2i64_v4i32, ARM64_INS_RADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv4i32_v4i16, ARM64_INS_RADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv4i32_v8i16, ARM64_INS_RADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv8i16_v16i8, ARM64_INS_RADDHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RADDHNv8i16_v8i8, ARM64_INS_RADDHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RBITWr, ARM64_INS_RBIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RBITXr, ARM64_INS_RBIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RBITv16i8, ARM64_INS_RBIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RBITv8i8, ARM64_INS_RBIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RET, ARM64_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_REV16Wr, ARM64_INS_REV16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_REV16Xr, ARM64_INS_REV16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_REV16v16i8, ARM64_INS_REV16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV16v8i8, ARM64_INS_REV16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV32Xr, ARM64_INS_REV32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_REV32v16i8, ARM64_INS_REV32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV32v4i16, ARM64_INS_REV32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV32v8i16, ARM64_INS_REV32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV32v8i8, ARM64_INS_REV32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v16i8, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v2i32, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v4i16, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v4i32, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v8i16, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REV64v8i8, ARM64_INS_REV64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_REVWr, ARM64_INS_REV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_REVXr, ARM64_INS_REV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RORVWr, ARM64_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RORVXr, ARM64_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv16i8_shift, ARM64_INS_RSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv2i32_shift, ARM64_INS_RSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv4i16_shift, ARM64_INS_RSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv4i32_shift, ARM64_INS_RSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv8i16_shift, ARM64_INS_RSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSHRNv8i8_shift, ARM64_INS_RSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv2i64_v2i32, ARM64_INS_RSUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv2i64_v4i32, ARM64_INS_RSUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv4i32_v4i16, ARM64_INS_RSUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv4i32_v8i16, ARM64_INS_RSUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv8i16_v16i8, ARM64_INS_RSUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_RSUBHNv8i16_v8i8, ARM64_INS_RSUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv16i8_v8i16, ARM64_INS_SABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv2i32_v2i64, ARM64_INS_SABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv4i16_v4i32, ARM64_INS_SABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv4i32_v2i64, ARM64_INS_SABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv8i16_v4i32, ARM64_INS_SABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABALv8i8_v8i16, ARM64_INS_SABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv16i8, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv2i32, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv4i16, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv4i32, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv8i16, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABAv8i8, ARM64_INS_SABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv16i8_v8i16, ARM64_INS_SABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv2i32_v2i64, ARM64_INS_SABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv4i16_v4i32, ARM64_INS_SABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv4i32_v2i64, ARM64_INS_SABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv8i16_v4i32, ARM64_INS_SABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDLv8i8_v8i16, ARM64_INS_SABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv16i8, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv2i32, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv4i16, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv4i32, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv8i16, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SABDv8i8, ARM64_INS_SABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv16i8_v8i16, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv2i32_v1i64, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv4i16_v2i32, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv4i32_v2i64, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv8i16_v4i32, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADALPv8i8_v4i16, ARM64_INS_SADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv16i8_v8i16, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv2i32_v1i64, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv4i16_v2i32, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv4i32_v2i64, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv8i16_v4i32, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLPv8i8_v4i16, ARM64_INS_SADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLVv16i8v, ARM64_INS_SADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLVv4i16v, ARM64_INS_SADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLVv4i32v, ARM64_INS_SADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLVv8i16v, ARM64_INS_SADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLVv8i8v, ARM64_INS_SADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv16i8_v8i16, ARM64_INS_SADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv2i32_v2i64, ARM64_INS_SADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv4i16_v4i32, ARM64_INS_SADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv4i32_v2i64, ARM64_INS_SADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv8i16_v4i32, ARM64_INS_SADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDLv8i8_v8i16, ARM64_INS_SADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv16i8_v8i16, ARM64_INS_SADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv2i32_v2i64, ARM64_INS_SADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv4i16_v4i32, ARM64_INS_SADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv4i32_v2i64, ARM64_INS_SADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv8i16_v4i32, ARM64_INS_SADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SADDWv8i8_v8i16, ARM64_INS_SADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SBCSWr, ARM64_INS_SBC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SBCSXr, ARM64_INS_SBC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SBCWr, ARM64_INS_SBC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SBCXr, ARM64_INS_SBC,
#ifndef CAPSTONE_DIET
		{ ARM64_REG_NZCV, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SBFMWri, ARM64_INS_SBFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SBFMXri, ARM64_INS_SBFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFSWDri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFSWSri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFSXDri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFSXSri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFUWDri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFUWSri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFUXDri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFUXSri, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFd, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFs, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv1i32, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv1i64, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv2f32, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv2f64, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv2i32_shift, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv2i64_shift, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv4f32, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SCVTFv4i32_shift, ARM64_INS_SCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SDIVWr, ARM64_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SDIVXr, ARM64_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SDIV_IntWr, ARM64_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SDIV_IntXr, ARM64_INS_SDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1Crrr, ARM64_INS_SHA1C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1Hrr, ARM64_INS_SHA1H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1Mrrr, ARM64_INS_SHA1M,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1Prrr, ARM64_INS_SHA1P,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1SU0rrr, ARM64_INS_SHA1SU0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA1SU1rr, ARM64_INS_SHA1SU1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA256H2rrr, ARM64_INS_SHA256H2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA256Hrrr, ARM64_INS_SHA256H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA256SU0rr, ARM64_INS_SHA256SU0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHA256SU1rrr, ARM64_INS_SHA256SU1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_CRYPTO, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv16i8, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv2i32, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv4i16, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv4i32, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv8i16, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHADDv8i8, ARM64_INS_SHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv16i8, ARM64_INS_SHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv2i32, ARM64_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv4i16, ARM64_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv4i32, ARM64_INS_SHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv8i16, ARM64_INS_SHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLLv8i8, ARM64_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLd, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv16i8_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv2i32_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv2i64_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv4i16_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv4i32_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv8i16_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHLv8i8_shift, ARM64_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv16i8_shift, ARM64_INS_SHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv2i32_shift, ARM64_INS_SHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv4i16_shift, ARM64_INS_SHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv4i32_shift, ARM64_INS_SHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv8i16_shift, ARM64_INS_SHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHRNv8i8_shift, ARM64_INS_SHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv16i8, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv2i32, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv4i16, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv4i32, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv8i16, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SHSUBv8i8, ARM64_INS_SHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLId, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv16i8_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv2i32_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv2i64_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv4i16_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv4i32_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv8i16_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SLIv8i8_shift, ARM64_INS_SLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMADDLrrr, ARM64_INS_SMADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv16i8, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv2i32, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv4i16, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv4i32, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv8i16, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXPv8i8, ARM64_INS_SMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXVv16i8v, ARM64_INS_SMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXVv4i16v, ARM64_INS_SMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXVv4i32v, ARM64_INS_SMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXVv8i16v, ARM64_INS_SMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXVv8i8v, ARM64_INS_SMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv16i8, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv2i32, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv4i16, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv4i32, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv8i16, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMAXv8i8, ARM64_INS_SMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMC, ARM64_INS_SMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv16i8, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv2i32, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv4i16, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv4i32, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv8i16, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINPv8i8, ARM64_INS_SMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINVv16i8v, ARM64_INS_SMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINVv4i16v, ARM64_INS_SMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINVv4i32v, ARM64_INS_SMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINVv8i16v, ARM64_INS_SMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINVv8i8v, ARM64_INS_SMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv16i8, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv2i32, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv4i16, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv4i32, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv8i16, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMINv8i8, ARM64_INS_SMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv16i8_v8i16, ARM64_INS_SMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv2i32_indexed, ARM64_INS_SMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv2i32_v2i64, ARM64_INS_SMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv4i16_indexed, ARM64_INS_SMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv4i16_v4i32, ARM64_INS_SMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv4i32_indexed, ARM64_INS_SMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv4i32_v2i64, ARM64_INS_SMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv8i16_indexed, ARM64_INS_SMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv8i16_v4i32, ARM64_INS_SMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLALv8i8_v8i16, ARM64_INS_SMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv16i8_v8i16, ARM64_INS_SMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv2i32_indexed, ARM64_INS_SMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv2i32_v2i64, ARM64_INS_SMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv4i16_indexed, ARM64_INS_SMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv4i16_v4i32, ARM64_INS_SMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv4i32_indexed, ARM64_INS_SMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv4i32_v2i64, ARM64_INS_SMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv8i16_indexed, ARM64_INS_SMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv8i16_v4i32, ARM64_INS_SMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMLSLv8i8_v8i16, ARM64_INS_SMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMOVvi16to32, ARM64_INS_SMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMOVvi16to64, ARM64_INS_SMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMOVvi32to64, ARM64_INS_SMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMOVvi8to32, ARM64_INS_SMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMOVvi8to64, ARM64_INS_SMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMSUBLrrr, ARM64_INS_SMSUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULHrr, ARM64_INS_SMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv16i8_v8i16, ARM64_INS_SMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv2i32_indexed, ARM64_INS_SMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv2i32_v2i64, ARM64_INS_SMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv4i16_indexed, ARM64_INS_SMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv4i16_v4i32, ARM64_INS_SMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv4i32_indexed, ARM64_INS_SMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv4i32_v2i64, ARM64_INS_SMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv8i16_indexed, ARM64_INS_SMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv8i16_v4i32, ARM64_INS_SMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SMULLv8i8_v8i16, ARM64_INS_SMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv16i8, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv1i16, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv1i32, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv1i64, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv1i8, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv2i32, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv2i64, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv4i16, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv4i32, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv8i16, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQABSv8i8, ARM64_INS_SQABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv16i8, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv1i16, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv1i32, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv1i64, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv1i8, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv2i32, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv2i64, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv4i16, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv4i32, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv8i16, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQADDv8i8, ARM64_INS_SQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALi16, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALi32, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv1i32_indexed, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv1i64_indexed, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv2i32_indexed, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv2i32_v2i64, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv4i16_indexed, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv4i16_v4i32, ARM64_INS_SQDMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv4i32_indexed, ARM64_INS_SQDMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv4i32_v2i64, ARM64_INS_SQDMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv8i16_indexed, ARM64_INS_SQDMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLALv8i16_v4i32, ARM64_INS_SQDMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLi16, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLi32, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv1i32_indexed, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv1i64_indexed, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv2i32_indexed, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv2i32_v2i64, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv4i16_indexed, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv4i16_v4i32, ARM64_INS_SQDMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv4i32_indexed, ARM64_INS_SQDMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv4i32_v2i64, ARM64_INS_SQDMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv8i16_indexed, ARM64_INS_SQDMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMLSLv8i16_v4i32, ARM64_INS_SQDMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv1i16, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv1i16_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv1i32, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv1i32_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv2i32, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv2i32_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv4i16, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv4i16_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv4i32, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv4i32_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv8i16, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULHv8i16_indexed, ARM64_INS_SQDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLi16, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLi32, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv1i32_indexed, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv1i64_indexed, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv2i32_indexed, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv2i32_v2i64, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv4i16_indexed, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv4i16_v4i32, ARM64_INS_SQDMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv4i32_indexed, ARM64_INS_SQDMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv4i32_v2i64, ARM64_INS_SQDMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv8i16_indexed, ARM64_INS_SQDMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQDMULLv8i16_v4i32, ARM64_INS_SQDMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv16i8, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv1i16, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv1i32, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv1i64, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv1i8, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv2i32, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv2i64, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv4i16, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv4i32, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv8i16, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQNEGv8i8, ARM64_INS_SQNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv1i16, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv1i16_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv1i32, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv1i32_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv2i32, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv2i32_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv4i16, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv4i16_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv4i32, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv4i32_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv8i16, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRDMULHv8i16_indexed, ARM64_INS_SQRDMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv16i8, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv1i16, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv1i32, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv1i64, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv1i8, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv2i32, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv2i64, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv4i16, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv4i32, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv8i16, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHLv8i8, ARM64_INS_SQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNb, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNh, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNs, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv16i8_shift, ARM64_INS_SQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv2i32_shift, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv4i16_shift, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv4i32_shift, ARM64_INS_SQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv8i16_shift, ARM64_INS_SQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRNv8i8_shift, ARM64_INS_SQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNb, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNh, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNs, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv16i8_shift, ARM64_INS_SQRSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv2i32_shift, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv4i16_shift, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv4i32_shift, ARM64_INS_SQRSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv8i16_shift, ARM64_INS_SQRSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQRSHRUNv8i8_shift, ARM64_INS_SQRSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUb, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUd, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUh, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUs, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv16i8_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv2i32_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv2i64_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv4i16_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv4i32_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv8i16_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLUv8i8_shift, ARM64_INS_SQSHLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLb, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLd, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLh, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLs, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv16i8, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv16i8_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv1i16, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv1i32, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv1i64, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv1i8, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv2i32, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv2i32_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv2i64, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv2i64_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv4i16, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv4i16_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv4i32, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv4i32_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv8i16, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv8i16_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv8i8, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHLv8i8_shift, ARM64_INS_SQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNb, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNh, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNs, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv16i8_shift, ARM64_INS_SQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv2i32_shift, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv4i16_shift, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv4i32_shift, ARM64_INS_SQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv8i16_shift, ARM64_INS_SQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRNv8i8_shift, ARM64_INS_SQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNb, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNh, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNs, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv16i8_shift, ARM64_INS_SQSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv2i32_shift, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv4i16_shift, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv4i32_shift, ARM64_INS_SQSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv8i16_shift, ARM64_INS_SQSHRUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSHRUNv8i8_shift, ARM64_INS_SQSHRUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv16i8, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv1i16, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv1i32, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv1i64, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv1i8, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv2i32, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv2i64, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv4i16, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv4i32, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv8i16, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQSUBv8i8, ARM64_INS_SQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv16i8, ARM64_INS_SQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv1i16, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv1i32, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv1i8, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv2i32, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv4i16, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv4i32, ARM64_INS_SQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv8i16, ARM64_INS_SQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTNv8i8, ARM64_INS_SQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv16i8, ARM64_INS_SQXTUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv1i16, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv1i32, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv1i8, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv2i32, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv4i16, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv4i32, ARM64_INS_SQXTUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv8i16, ARM64_INS_SQXTUN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SQXTUNv8i8, ARM64_INS_SQXTUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv16i8, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv2i32, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv4i16, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv4i32, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv8i16, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRHADDv8i8, ARM64_INS_SRHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRId, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv16i8_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv2i32_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv2i64_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv4i16_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv4i32_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv8i16_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRIv8i8_shift, ARM64_INS_SRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv16i8, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv1i64, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv2i32, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv2i64, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv4i16, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv4i32, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv8i16, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHLv8i8, ARM64_INS_SRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRd, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv16i8_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv2i32_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv2i64_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv4i16_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv4i32_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv8i16_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSHRv8i8_shift, ARM64_INS_SRSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAd, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv16i8_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv2i32_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv2i64_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv4i16_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv4i32_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv8i16_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SRSRAv8i8_shift, ARM64_INS_SRSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv16i8_shift, ARM64_INS_SSHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv2i32_shift, ARM64_INS_SSHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv4i16_shift, ARM64_INS_SSHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv4i32_shift, ARM64_INS_SSHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv8i16_shift, ARM64_INS_SSHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLLv8i8_shift, ARM64_INS_SSHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv16i8, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv1i64, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv2i32, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv2i64, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv4i16, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv4i32, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv8i16, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHLv8i8, ARM64_INS_SSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRd, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv16i8_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv2i32_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv2i64_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv4i16_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv4i32_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv8i16_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSHRv8i8_shift, ARM64_INS_SSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAd, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv16i8_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv2i32_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv2i64_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv4i16_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv4i32_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv8i16_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSRAv8i8_shift, ARM64_INS_SSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv16i8_v8i16, ARM64_INS_SSUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv2i32_v2i64, ARM64_INS_SSUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv4i16_v4i32, ARM64_INS_SSUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv4i32_v2i64, ARM64_INS_SSUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv8i16_v4i32, ARM64_INS_SSUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBLv8i8_v8i16, ARM64_INS_SSUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv16i8_v8i16, ARM64_INS_SSUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv2i32_v2i64, ARM64_INS_SSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv4i16_v4i32, ARM64_INS_SSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv4i32_v2i64, ARM64_INS_SSUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv8i16_v4i32, ARM64_INS_SSUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SSUBWv8i8_v8i16, ARM64_INS_SSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv16b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv16b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv1d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv1d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv2d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv2d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv2s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv2s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv4h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv4h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv4s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv4s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv8b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv8b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv8h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Fourv8h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev16b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev16b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev1d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev1d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev2d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev2d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev2s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev2s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev4h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev4h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev4s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev4s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev8b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev8b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev8h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Onev8h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev16b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev16b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev1d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev1d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev2d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev2d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev2s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev2s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev4h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev4h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev4s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev4s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev8b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev8b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev8h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Threev8h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov16b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov16b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov1d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov1d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov2d, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov2d_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov2s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov2s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov4h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov4h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov4s, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov4s_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov8b, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov8b_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov8h, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1Twov8h_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i16, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i16_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i32, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i32_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i64, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i64_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i8, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST1i8_POST, ARM64_INS_ST1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov16b, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov16b_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov2d, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov2d_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov2s, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov2s_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov4h, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov4h_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov4s, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov4s_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov8b, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov8b_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov8h, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2Twov8h_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i16, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i16_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i32, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i32_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i64, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i64_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i8, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST2i8_POST, ARM64_INS_ST2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev16b, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev16b_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev2d, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev2d_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev2s, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev2s_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev4h, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev4h_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev4s, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev4s_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev8b, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev8b_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev8h, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3Threev8h_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i16, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i16_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i32, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i32_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i64, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i64_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i8, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST3i8_POST, ARM64_INS_ST3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv16b, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv16b_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv2d, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv2d_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv2s, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv2s_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv4h, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv4h_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv4s, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv4s_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv8b, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv8b_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv8h, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4Fourv8h_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i16, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i16_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i32, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i32_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i64, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i64_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i8, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ST4i8_POST, ARM64_INS_ST4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_STLRB, ARM64_INS_STLRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLRH, ARM64_INS_STLRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLRW, ARM64_INS_STLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLRX, ARM64_INS_STLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXPW, ARM64_INS_STLXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXPX, ARM64_INS_STLXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXRB, ARM64_INS_STLXRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXRH, ARM64_INS_STLXRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXRW, ARM64_INS_STLXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STLXRX, ARM64_INS_STLXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STNPDi, ARM64_INS_STNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STNPQi, ARM64_INS_STNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STNPSi, ARM64_INS_STNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STNPWi, ARM64_INS_STNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STNPXi, ARM64_INS_STNP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPDi, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPDpost, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPDpre, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPQi, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPQpost, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPQpre, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPSi, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPSpost, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPSpre, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPWi, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPWpost, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPWpre, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPXi, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPXpost, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STPXpre, ARM64_INS_STP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBBpost, ARM64_INS_STRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBBpre, ARM64_INS_STRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBBroW, ARM64_INS_STRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBBroX, ARM64_INS_STRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBBui, ARM64_INS_STRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRBui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRDpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRDpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRDroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRDroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRDui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHHpost, ARM64_INS_STRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHHpre, ARM64_INS_STRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHHroW, ARM64_INS_STRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHHroX, ARM64_INS_STRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHHui, ARM64_INS_STRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRHui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRQpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRQpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRQroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRQroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRQui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRSpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRSpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRSroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRSroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRSui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRWpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRWpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRWroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRWroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRWui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRXpost, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRXpre, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRXroW, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRXroX, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STRXui, ARM64_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STTRBi, ARM64_INS_STTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STTRHi, ARM64_INS_STTRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STTRWi, ARM64_INS_STTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STTRXi, ARM64_INS_STTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURBBi, ARM64_INS_STURB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURBi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURDi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURHHi, ARM64_INS_STURH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURHi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURQi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURSi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURWi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STURXi, ARM64_INS_STUR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXPW, ARM64_INS_STXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXPX, ARM64_INS_STXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXRB, ARM64_INS_STXRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXRH, ARM64_INS_STXRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXRW, ARM64_INS_STXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_STXRX, ARM64_INS_STXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv2i64_v2i32, ARM64_INS_SUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv2i64_v4i32, ARM64_INS_SUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv4i32_v4i16, ARM64_INS_SUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv4i32_v8i16, ARM64_INS_SUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv8i16_v16i8, ARM64_INS_SUBHN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBHNv8i16_v8i8, ARM64_INS_SUBHN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSWri, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSWrs, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSWrx, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSXri, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSXrs, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSXrx, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBSXrx64, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { ARM64_REG_NZCV, 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBWri, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBWrs, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBWrx, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBXri, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBXrs, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBXrx, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBXrx64, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv16i8, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv1i64, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv2i32, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv2i64, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv4i16, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv4i32, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv8i16, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUBv8i8, ARM64_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv16i8, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv1i16, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv1i32, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv1i64, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv1i8, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv2i32, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv2i64, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv4i16, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv4i32, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv8i16, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SUQADDv8i8, ARM64_INS_SUQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_SVC, ARM64_INS_SVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SYSLxt, ARM64_INS_SYSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_SYSxt, ARM64_INS_SYS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv16i8Four, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv16i8One, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv16i8Three, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv16i8Two, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv8i8Four, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv8i8One, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv8i8Three, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBLv8i8Two, ARM64_INS_TBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBNZW, ARM64_INS_TBNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_TBNZX, ARM64_INS_TBNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_TBXv16i8Four, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv16i8One, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv16i8Three, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv16i8Two, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv8i8Four, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv8i8One, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv8i8Three, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBXv8i8Two, ARM64_INS_TBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TBZW, ARM64_INS_TBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_TBZX, ARM64_INS_TBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		AArch64_TRN1v16i8, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v2i32, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v2i64, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v4i16, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v4i32, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v8i16, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN1v8i8, ARM64_INS_TRN1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v16i8, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v2i32, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v2i64, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v4i16, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v4i32, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v8i16, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_TRN2v8i8, ARM64_INS_TRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv16i8_v8i16, ARM64_INS_UABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv2i32_v2i64, ARM64_INS_UABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv4i16_v4i32, ARM64_INS_UABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv4i32_v2i64, ARM64_INS_UABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv8i16_v4i32, ARM64_INS_UABAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABALv8i8_v8i16, ARM64_INS_UABAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv16i8, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv2i32, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv4i16, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv4i32, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv8i16, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABAv8i8, ARM64_INS_UABA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv16i8_v8i16, ARM64_INS_UABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv2i32_v2i64, ARM64_INS_UABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv4i16_v4i32, ARM64_INS_UABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv4i32_v2i64, ARM64_INS_UABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv8i16_v4i32, ARM64_INS_UABDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDLv8i8_v8i16, ARM64_INS_UABDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv16i8, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv2i32, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv4i16, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv4i32, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv8i16, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UABDv8i8, ARM64_INS_UABD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv16i8_v8i16, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv2i32_v1i64, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv4i16_v2i32, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv4i32_v2i64, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv8i16_v4i32, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADALPv8i8_v4i16, ARM64_INS_UADALP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv16i8_v8i16, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv2i32_v1i64, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv4i16_v2i32, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv4i32_v2i64, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv8i16_v4i32, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLPv8i8_v4i16, ARM64_INS_UADDLP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLVv16i8v, ARM64_INS_UADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLVv4i16v, ARM64_INS_UADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLVv4i32v, ARM64_INS_UADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLVv8i16v, ARM64_INS_UADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLVv8i8v, ARM64_INS_UADDLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv16i8_v8i16, ARM64_INS_UADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv2i32_v2i64, ARM64_INS_UADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv4i16_v4i32, ARM64_INS_UADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv4i32_v2i64, ARM64_INS_UADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv8i16_v4i32, ARM64_INS_UADDL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDLv8i8_v8i16, ARM64_INS_UADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv16i8_v8i16, ARM64_INS_UADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv2i32_v2i64, ARM64_INS_UADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv4i16_v4i32, ARM64_INS_UADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv4i32_v2i64, ARM64_INS_UADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv8i16_v4i32, ARM64_INS_UADDW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UADDWv8i8_v8i16, ARM64_INS_UADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UBFMWri, ARM64_INS_UBFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UBFMXri, ARM64_INS_UBFM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFSWDri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFSWSri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFSXDri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFSXSri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFUWDri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFUWSri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFUXDri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFUXSri, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_FPARMV8, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFd, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFs, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv1i32, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv1i64, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv2f32, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv2f64, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv2i32_shift, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv2i64_shift, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv4f32, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UCVTFv4i32_shift, ARM64_INS_UCVTF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UDIVWr, ARM64_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UDIVXr, ARM64_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UDIV_IntWr, ARM64_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UDIV_IntXr, ARM64_INS_UDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv16i8, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv2i32, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv4i16, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv4i32, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv8i16, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHADDv8i8, ARM64_INS_UHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv16i8, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv2i32, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv4i16, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv4i32, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv8i16, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UHSUBv8i8, ARM64_INS_UHSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMADDLrrr, ARM64_INS_UMADDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv16i8, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv2i32, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv4i16, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv4i32, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv8i16, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXPv8i8, ARM64_INS_UMAXP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXVv16i8v, ARM64_INS_UMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXVv4i16v, ARM64_INS_UMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXVv4i32v, ARM64_INS_UMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXVv8i16v, ARM64_INS_UMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXVv8i8v, ARM64_INS_UMAXV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv16i8, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv2i32, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv4i16, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv4i32, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv8i16, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMAXv8i8, ARM64_INS_UMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv16i8, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv2i32, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv4i16, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv4i32, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv8i16, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINPv8i8, ARM64_INS_UMINP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINVv16i8v, ARM64_INS_UMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINVv4i16v, ARM64_INS_UMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINVv4i32v, ARM64_INS_UMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINVv8i16v, ARM64_INS_UMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINVv8i8v, ARM64_INS_UMINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv16i8, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv2i32, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv4i16, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv4i32, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv8i16, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMINv8i8, ARM64_INS_UMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv16i8_v8i16, ARM64_INS_UMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv2i32_indexed, ARM64_INS_UMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv2i32_v2i64, ARM64_INS_UMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv4i16_indexed, ARM64_INS_UMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv4i16_v4i32, ARM64_INS_UMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv4i32_indexed, ARM64_INS_UMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv4i32_v2i64, ARM64_INS_UMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv8i16_indexed, ARM64_INS_UMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv8i16_v4i32, ARM64_INS_UMLAL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLALv8i8_v8i16, ARM64_INS_UMLAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv16i8_v8i16, ARM64_INS_UMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv2i32_indexed, ARM64_INS_UMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv2i32_v2i64, ARM64_INS_UMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv4i16_indexed, ARM64_INS_UMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv4i16_v4i32, ARM64_INS_UMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv4i32_indexed, ARM64_INS_UMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv4i32_v2i64, ARM64_INS_UMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv8i16_indexed, ARM64_INS_UMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv8i16_v4i32, ARM64_INS_UMLSL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMLSLv8i8_v8i16, ARM64_INS_UMLSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMOVvi16, ARM64_INS_UMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMOVvi32, ARM64_INS_UMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMOVvi64, ARM64_INS_UMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMOVvi8, ARM64_INS_UMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMSUBLrrr, ARM64_INS_UMSUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULHrr, ARM64_INS_UMULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv16i8_v8i16, ARM64_INS_UMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv2i32_indexed, ARM64_INS_UMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv2i32_v2i64, ARM64_INS_UMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv4i16_indexed, ARM64_INS_UMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv4i16_v4i32, ARM64_INS_UMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv4i32_indexed, ARM64_INS_UMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv4i32_v2i64, ARM64_INS_UMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv8i16_indexed, ARM64_INS_UMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv8i16_v4i32, ARM64_INS_UMULL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UMULLv8i8_v8i16, ARM64_INS_UMULL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv16i8, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv1i16, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv1i32, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv1i64, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv1i8, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv2i32, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv2i64, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv4i16, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv4i32, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv8i16, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQADDv8i8, ARM64_INS_UQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv16i8, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv1i16, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv1i32, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv1i64, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv1i8, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv2i32, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv2i64, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv4i16, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv4i32, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv8i16, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHLv8i8, ARM64_INS_UQRSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNb, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNh, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNs, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv16i8_shift, ARM64_INS_UQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv2i32_shift, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv4i16_shift, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv4i32_shift, ARM64_INS_UQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv8i16_shift, ARM64_INS_UQRSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQRSHRNv8i8_shift, ARM64_INS_UQRSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLb, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLd, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLh, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLs, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv16i8, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv16i8_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv1i16, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv1i32, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv1i64, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv1i8, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv2i32, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv2i32_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv2i64, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv2i64_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv4i16, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv4i16_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv4i32, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv4i32_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv8i16, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv8i16_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv8i8, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHLv8i8_shift, ARM64_INS_UQSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNb, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNh, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNs, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv16i8_shift, ARM64_INS_UQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv2i32_shift, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv4i16_shift, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv4i32_shift, ARM64_INS_UQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv8i16_shift, ARM64_INS_UQSHRN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSHRNv8i8_shift, ARM64_INS_UQSHRN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv16i8, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv1i16, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv1i32, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv1i64, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv1i8, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv2i32, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv2i64, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv4i16, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv4i32, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv8i16, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQSUBv8i8, ARM64_INS_UQSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv16i8, ARM64_INS_UQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv1i16, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv1i32, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv1i8, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv2i32, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv4i16, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv4i32, ARM64_INS_UQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv8i16, ARM64_INS_UQXTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UQXTNv8i8, ARM64_INS_UQXTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URECPEv2i32, ARM64_INS_URECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URECPEv4i32, ARM64_INS_URECPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv16i8, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv2i32, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv4i16, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv4i32, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv8i16, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URHADDv8i8, ARM64_INS_URHADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv16i8, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv1i64, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv2i32, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv2i64, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv4i16, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv4i32, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv8i16, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHLv8i8, ARM64_INS_URSHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRd, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv16i8_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv2i32_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv2i64_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv4i16_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv4i32_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv8i16_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSHRv8i8_shift, ARM64_INS_URSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSQRTEv2i32, ARM64_INS_URSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSQRTEv4i32, ARM64_INS_URSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAd, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv16i8_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv2i32_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv2i64_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv4i16_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv4i32_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv8i16_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_URSRAv8i8_shift, ARM64_INS_URSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv16i8_shift, ARM64_INS_USHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv2i32_shift, ARM64_INS_USHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv4i16_shift, ARM64_INS_USHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv4i32_shift, ARM64_INS_USHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv8i16_shift, ARM64_INS_USHLL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLLv8i8_shift, ARM64_INS_USHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv16i8, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv1i64, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv2i32, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv2i64, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv4i16, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv4i32, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv8i16, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHLv8i8, ARM64_INS_USHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRd, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv16i8_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv2i32_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv2i64_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv4i16_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv4i32_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv8i16_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USHRv8i8_shift, ARM64_INS_USHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv16i8, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv1i16, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv1i32, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv1i64, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv1i8, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv2i32, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv2i64, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv4i16, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv4i32, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv8i16, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USQADDv8i8, ARM64_INS_USQADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAd, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv16i8_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv2i32_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv2i64_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv4i16_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv4i32_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv8i16_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USRAv8i8_shift, ARM64_INS_USRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv16i8_v8i16, ARM64_INS_USUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv2i32_v2i64, ARM64_INS_USUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv4i16_v4i32, ARM64_INS_USUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv4i32_v2i64, ARM64_INS_USUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv8i16_v4i32, ARM64_INS_USUBL2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBLv8i8_v8i16, ARM64_INS_USUBL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv16i8_v8i16, ARM64_INS_USUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv2i32_v2i64, ARM64_INS_USUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv4i16_v4i32, ARM64_INS_USUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv4i32_v2i64, ARM64_INS_USUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv8i16_v4i32, ARM64_INS_USUBW2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_USUBWv8i8_v8i16, ARM64_INS_USUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v16i8, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v2i32, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v2i64, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v4i16, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v4i32, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v8i16, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP1v8i8, ARM64_INS_UZP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v16i8, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v2i32, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v2i64, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v4i16, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v4i32, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v8i16, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_UZP2v8i8, ARM64_INS_UZP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv16i8, ARM64_INS_XTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv2i32, ARM64_INS_XTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv4i16, ARM64_INS_XTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv4i32, ARM64_INS_XTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv8i16, ARM64_INS_XTN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_XTNv8i8, ARM64_INS_XTN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v16i8, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v2i32, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v2i64, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v4i16, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v4i32, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v8i16, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP1v8i8, ARM64_INS_ZIP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v16i8, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v2i32, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v2i64, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v4i16, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v4i32, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v8i16, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
	{
		AArch64_ZIP2v8i8, ARM64_INS_ZIP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { ARM64_GRP_NEON, 0 }, 0, 0
#endif
	},
};

// some alias instruction only need to be defined locally to satisfy
// some lookup functions
// just make sure these IDs never reuse any other IDs ARM_INS_*
#define ARM64_INS_NEGS (unsigned short)-1
#define ARM64_INS_NGCS (unsigned short)-2

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			cs_struct handle;
			handle.detail = h->detail;

			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

			insn->detail->arm64.update_flags = cs_reg_write((csh)&handle, insn, ARM64_REG_NZCV);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = ARM64_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

static name_map insn_name_maps[] = {
	{ ARM64_INS_INVALID, NULL },

	{ ARM64_INS_ABS, "abs" },
	{ ARM64_INS_ADC, "adc" },
	{ ARM64_INS_ADDHN, "addhn" },
	{ ARM64_INS_ADDHN2, "addhn2" },
	{ ARM64_INS_ADDP, "addp" },
	{ ARM64_INS_ADD, "add" },
	{ ARM64_INS_ADDV, "addv" },
	{ ARM64_INS_ADR, "adr" },
	{ ARM64_INS_ADRP, "adrp" },
	{ ARM64_INS_AESD, "aesd" },
	{ ARM64_INS_AESE, "aese" },
	{ ARM64_INS_AESIMC, "aesimc" },
	{ ARM64_INS_AESMC, "aesmc" },
	{ ARM64_INS_AND, "and" },
	{ ARM64_INS_ASR, "asr" },
	{ ARM64_INS_B, "b" },
	{ ARM64_INS_BFM, "bfm" },
	{ ARM64_INS_BIC, "bic" },
	{ ARM64_INS_BIF, "bif" },
	{ ARM64_INS_BIT, "bit" },
	{ ARM64_INS_BL, "bl" },
	{ ARM64_INS_BLR, "blr" },
	{ ARM64_INS_BR, "br" },
	{ ARM64_INS_BRK, "brk" },
	{ ARM64_INS_BSL, "bsl" },
	{ ARM64_INS_CBNZ, "cbnz" },
	{ ARM64_INS_CBZ, "cbz" },
	{ ARM64_INS_CCMN, "ccmn" },
	{ ARM64_INS_CCMP, "ccmp" },
	{ ARM64_INS_CLREX, "clrex" },
	{ ARM64_INS_CLS, "cls" },
	{ ARM64_INS_CLZ, "clz" },
	{ ARM64_INS_CMEQ, "cmeq" },
	{ ARM64_INS_CMGE, "cmge" },
	{ ARM64_INS_CMGT, "cmgt" },
	{ ARM64_INS_CMHI, "cmhi" },
	{ ARM64_INS_CMHS, "cmhs" },
	{ ARM64_INS_CMLE, "cmle" },
	{ ARM64_INS_CMLT, "cmlt" },
	{ ARM64_INS_CMTST, "cmtst" },
	{ ARM64_INS_CNT, "cnt" },
	{ ARM64_INS_MOV, "mov" },
	{ ARM64_INS_CRC32B, "crc32b" },
	{ ARM64_INS_CRC32CB, "crc32cb" },
	{ ARM64_INS_CRC32CH, "crc32ch" },
	{ ARM64_INS_CRC32CW, "crc32cw" },
	{ ARM64_INS_CRC32CX, "crc32cx" },
	{ ARM64_INS_CRC32H, "crc32h" },
	{ ARM64_INS_CRC32W, "crc32w" },
	{ ARM64_INS_CRC32X, "crc32x" },
	{ ARM64_INS_CSEL, "csel" },
	{ ARM64_INS_CSINC, "csinc" },
	{ ARM64_INS_CSINV, "csinv" },
	{ ARM64_INS_CSNEG, "csneg" },
	{ ARM64_INS_DCPS1, "dcps1" },
	{ ARM64_INS_DCPS2, "dcps2" },
	{ ARM64_INS_DCPS3, "dcps3" },
	{ ARM64_INS_DMB, "dmb" },
	{ ARM64_INS_DRPS, "drps" },
	{ ARM64_INS_DSB, "dsb" },
	{ ARM64_INS_DUP, "dup" },
	{ ARM64_INS_EON, "eon" },
	{ ARM64_INS_EOR, "eor" },
	{ ARM64_INS_ERET, "eret" },
	{ ARM64_INS_EXTR, "extr" },
	{ ARM64_INS_EXT, "ext" },
	{ ARM64_INS_FABD, "fabd" },
	{ ARM64_INS_FABS, "fabs" },
	{ ARM64_INS_FACGE, "facge" },
	{ ARM64_INS_FACGT, "facgt" },
	{ ARM64_INS_FADD, "fadd" },
	{ ARM64_INS_FADDP, "faddp" },
	{ ARM64_INS_FCCMP, "fccmp" },
	{ ARM64_INS_FCCMPE, "fccmpe" },
	{ ARM64_INS_FCMEQ, "fcmeq" },
	{ ARM64_INS_FCMGE, "fcmge" },
	{ ARM64_INS_FCMGT, "fcmgt" },
	{ ARM64_INS_FCMLE, "fcmle" },
	{ ARM64_INS_FCMLT, "fcmlt" },
	{ ARM64_INS_FCMP, "fcmp" },
	{ ARM64_INS_FCMPE, "fcmpe" },
	{ ARM64_INS_FCSEL, "fcsel" },
	{ ARM64_INS_FCVTAS, "fcvtas" },
	{ ARM64_INS_FCVTAU, "fcvtau" },
	{ ARM64_INS_FCVT, "fcvt" },
	{ ARM64_INS_FCVTL, "fcvtl" },
	{ ARM64_INS_FCVTL2, "fcvtl2" },
	{ ARM64_INS_FCVTMS, "fcvtms" },
	{ ARM64_INS_FCVTMU, "fcvtmu" },
	{ ARM64_INS_FCVTNS, "fcvtns" },
	{ ARM64_INS_FCVTNU, "fcvtnu" },
	{ ARM64_INS_FCVTN, "fcvtn" },
	{ ARM64_INS_FCVTN2, "fcvtn2" },
	{ ARM64_INS_FCVTPS, "fcvtps" },
	{ ARM64_INS_FCVTPU, "fcvtpu" },
	{ ARM64_INS_FCVTXN, "fcvtxn" },
	{ ARM64_INS_FCVTXN2, "fcvtxn2" },
	{ ARM64_INS_FCVTZS, "fcvtzs" },
	{ ARM64_INS_FCVTZU, "fcvtzu" },
	{ ARM64_INS_FDIV, "fdiv" },
	{ ARM64_INS_FMADD, "fmadd" },
	{ ARM64_INS_FMAX, "fmax" },
	{ ARM64_INS_FMAXNM, "fmaxnm" },
	{ ARM64_INS_FMAXNMP, "fmaxnmp" },
	{ ARM64_INS_FMAXNMV, "fmaxnmv" },
	{ ARM64_INS_FMAXP, "fmaxp" },
	{ ARM64_INS_FMAXV, "fmaxv" },
	{ ARM64_INS_FMIN, "fmin" },
	{ ARM64_INS_FMINNM, "fminnm" },
	{ ARM64_INS_FMINNMP, "fminnmp" },
	{ ARM64_INS_FMINNMV, "fminnmv" },
	{ ARM64_INS_FMINP, "fminp" },
	{ ARM64_INS_FMINV, "fminv" },
	{ ARM64_INS_FMLA, "fmla" },
	{ ARM64_INS_FMLS, "fmls" },
	{ ARM64_INS_FMOV, "fmov" },
	{ ARM64_INS_FMSUB, "fmsub" },
	{ ARM64_INS_FMUL, "fmul" },
	{ ARM64_INS_FMULX, "fmulx" },
	{ ARM64_INS_FNEG, "fneg" },
	{ ARM64_INS_FNMADD, "fnmadd" },
	{ ARM64_INS_FNMSUB, "fnmsub" },
	{ ARM64_INS_FNMUL, "fnmul" },
	{ ARM64_INS_FRECPE, "frecpe" },
	{ ARM64_INS_FRECPS, "frecps" },
	{ ARM64_INS_FRECPX, "frecpx" },
	{ ARM64_INS_FRINTA, "frinta" },
	{ ARM64_INS_FRINTI, "frinti" },
	{ ARM64_INS_FRINTM, "frintm" },
	{ ARM64_INS_FRINTN, "frintn" },
	{ ARM64_INS_FRINTP, "frintp" },
	{ ARM64_INS_FRINTX, "frintx" },
	{ ARM64_INS_FRINTZ, "frintz" },
	{ ARM64_INS_FRSQRTE, "frsqrte" },
	{ ARM64_INS_FRSQRTS, "frsqrts" },
	{ ARM64_INS_FSQRT, "fsqrt" },
	{ ARM64_INS_FSUB, "fsub" },
	{ ARM64_INS_HINT, "hint" },
	{ ARM64_INS_HLT, "hlt" },
	{ ARM64_INS_HVC, "hvc" },
	{ ARM64_INS_INS, "ins" },
	{ ARM64_INS_ISB, "isb" },
	{ ARM64_INS_LD1, "ld1" },
	{ ARM64_INS_LD1R, "ld1r" },
	{ ARM64_INS_LD2R, "ld2r" },
	{ ARM64_INS_LD2, "ld2" },
	{ ARM64_INS_LD3R, "ld3r" },
	{ ARM64_INS_LD3, "ld3" },
	{ ARM64_INS_LD4, "ld4" },
	{ ARM64_INS_LD4R, "ld4r" },
	{ ARM64_INS_LDARB, "ldarb" },
	{ ARM64_INS_LDARH, "ldarh" },
	{ ARM64_INS_LDAR, "ldar" },
	{ ARM64_INS_LDAXP, "ldaxp" },
	{ ARM64_INS_LDAXRB, "ldaxrb" },
	{ ARM64_INS_LDAXRH, "ldaxrh" },
	{ ARM64_INS_LDAXR, "ldaxr" },
	{ ARM64_INS_LDNP, "ldnp" },
	{ ARM64_INS_LDP, "ldp" },
	{ ARM64_INS_LDPSW, "ldpsw" },
	{ ARM64_INS_LDRB, "ldrb" },
	{ ARM64_INS_LDR, "ldr" },
	{ ARM64_INS_LDRH, "ldrh" },
	{ ARM64_INS_LDRSB, "ldrsb" },
	{ ARM64_INS_LDRSH, "ldrsh" },
	{ ARM64_INS_LDRSW, "ldrsw" },
	{ ARM64_INS_LDTRB, "ldtrb" },
	{ ARM64_INS_LDTRH, "ldtrh" },
	{ ARM64_INS_LDTRSB, "ldtrsb" },
	{ ARM64_INS_LDTRSH, "ldtrsh" },
	{ ARM64_INS_LDTRSW, "ldtrsw" },
	{ ARM64_INS_LDTR, "ldtr" },
	{ ARM64_INS_LDURB, "ldurb" },
	{ ARM64_INS_LDUR, "ldur" },
	{ ARM64_INS_LDURH, "ldurh" },
	{ ARM64_INS_LDURSB, "ldursb" },
	{ ARM64_INS_LDURSH, "ldursh" },
	{ ARM64_INS_LDURSW, "ldursw" },
	{ ARM64_INS_LDXP, "ldxp" },
	{ ARM64_INS_LDXRB, "ldxrb" },
	{ ARM64_INS_LDXRH, "ldxrh" },
	{ ARM64_INS_LDXR, "ldxr" },
	{ ARM64_INS_LSL, "lsl" },
	{ ARM64_INS_LSR, "lsr" },
	{ ARM64_INS_MADD, "madd" },
	{ ARM64_INS_MLA, "mla" },
	{ ARM64_INS_MLS, "mls" },
	{ ARM64_INS_MOVI, "movi" },
	{ ARM64_INS_MOVK, "movk" },
	{ ARM64_INS_MOVN, "movn" },
	{ ARM64_INS_MOVZ, "movz" },
	{ ARM64_INS_MRS, "mrs" },
	{ ARM64_INS_MSR, "msr" },
	{ ARM64_INS_MSUB, "msub" },
	{ ARM64_INS_MUL, "mul" },
	{ ARM64_INS_MVNI, "mvni" },
	{ ARM64_INS_NEG, "neg" },
	{ ARM64_INS_NOT, "not" },
	{ ARM64_INS_ORN, "orn" },
	{ ARM64_INS_ORR, "orr" },
	{ ARM64_INS_PMULL2, "pmull2" },
	{ ARM64_INS_PMULL, "pmull" },
	{ ARM64_INS_PMUL, "pmul" },
	{ ARM64_INS_PRFM, "prfm" },
	{ ARM64_INS_PRFUM, "prfum" },
	{ ARM64_INS_RADDHN, "raddhn" },
	{ ARM64_INS_RADDHN2, "raddhn2" },
	{ ARM64_INS_RBIT, "rbit" },
	{ ARM64_INS_RET, "ret" },
	{ ARM64_INS_REV16, "rev16" },
	{ ARM64_INS_REV32, "rev32" },
	{ ARM64_INS_REV64, "rev64" },
	{ ARM64_INS_REV, "rev" },
	{ ARM64_INS_ROR, "ror" },
	{ ARM64_INS_RSHRN2, "rshrn2" },
	{ ARM64_INS_RSHRN, "rshrn" },
	{ ARM64_INS_RSUBHN, "rsubhn" },
	{ ARM64_INS_RSUBHN2, "rsubhn2" },
	{ ARM64_INS_SABAL2, "sabal2" },
	{ ARM64_INS_SABAL, "sabal" },
	{ ARM64_INS_SABA, "saba" },
	{ ARM64_INS_SABDL2, "sabdl2" },
	{ ARM64_INS_SABDL, "sabdl" },
	{ ARM64_INS_SABD, "sabd" },
	{ ARM64_INS_SADALP, "sadalp" },
	{ ARM64_INS_SADDLP, "saddlp" },
	{ ARM64_INS_SADDLV, "saddlv" },
	{ ARM64_INS_SADDL2, "saddl2" },
	{ ARM64_INS_SADDL, "saddl" },
	{ ARM64_INS_SADDW2, "saddw2" },
	{ ARM64_INS_SADDW, "saddw" },
	{ ARM64_INS_SBC, "sbc" },
	{ ARM64_INS_SBFM, "sbfm" },
	{ ARM64_INS_SCVTF, "scvtf" },
	{ ARM64_INS_SDIV, "sdiv" },
	{ ARM64_INS_SHA1C, "sha1c" },
	{ ARM64_INS_SHA1H, "sha1h" },
	{ ARM64_INS_SHA1M, "sha1m" },
	{ ARM64_INS_SHA1P, "sha1p" },
	{ ARM64_INS_SHA1SU0, "sha1su0" },
	{ ARM64_INS_SHA1SU1, "sha1su1" },
	{ ARM64_INS_SHA256H2, "sha256h2" },
	{ ARM64_INS_SHA256H, "sha256h" },
	{ ARM64_INS_SHA256SU0, "sha256su0" },
	{ ARM64_INS_SHA256SU1, "sha256su1" },
	{ ARM64_INS_SHADD, "shadd" },
	{ ARM64_INS_SHLL2, "shll2" },
	{ ARM64_INS_SHLL, "shll" },
	{ ARM64_INS_SHL, "shl" },
	{ ARM64_INS_SHRN2, "shrn2" },
	{ ARM64_INS_SHRN, "shrn" },
	{ ARM64_INS_SHSUB, "shsub" },
	{ ARM64_INS_SLI, "sli" },
	{ ARM64_INS_SMADDL, "smaddl" },
	{ ARM64_INS_SMAXP, "smaxp" },
	{ ARM64_INS_SMAXV, "smaxv" },
	{ ARM64_INS_SMAX, "smax" },
	{ ARM64_INS_SMC, "smc" },
	{ ARM64_INS_SMINP, "sminp" },
	{ ARM64_INS_SMINV, "sminv" },
	{ ARM64_INS_SMIN, "smin" },
	{ ARM64_INS_SMLAL2, "smlal2" },
	{ ARM64_INS_SMLAL, "smlal" },
	{ ARM64_INS_SMLSL2, "smlsl2" },
	{ ARM64_INS_SMLSL, "smlsl" },
	{ ARM64_INS_SMOV, "smov" },
	{ ARM64_INS_SMSUBL, "smsubl" },
	{ ARM64_INS_SMULH, "smulh" },
	{ ARM64_INS_SMULL2, "smull2" },
	{ ARM64_INS_SMULL, "smull" },
	{ ARM64_INS_SQABS, "sqabs" },
	{ ARM64_INS_SQADD, "sqadd" },
	{ ARM64_INS_SQDMLAL, "sqdmlal" },
	{ ARM64_INS_SQDMLAL2, "sqdmlal2" },
	{ ARM64_INS_SQDMLSL, "sqdmlsl" },
	{ ARM64_INS_SQDMLSL2, "sqdmlsl2" },
	{ ARM64_INS_SQDMULH, "sqdmulh" },
	{ ARM64_INS_SQDMULL, "sqdmull" },
	{ ARM64_INS_SQDMULL2, "sqdmull2" },
	{ ARM64_INS_SQNEG, "sqneg" },
	{ ARM64_INS_SQRDMULH, "sqrdmulh" },
	{ ARM64_INS_SQRSHL, "sqrshl" },
	{ ARM64_INS_SQRSHRN, "sqrshrn" },
	{ ARM64_INS_SQRSHRN2, "sqrshrn2" },
	{ ARM64_INS_SQRSHRUN, "sqrshrun" },
	{ ARM64_INS_SQRSHRUN2, "sqrshrun2" },
	{ ARM64_INS_SQSHLU, "sqshlu" },
	{ ARM64_INS_SQSHL, "sqshl" },
	{ ARM64_INS_SQSHRN, "sqshrn" },
	{ ARM64_INS_SQSHRN2, "sqshrn2" },
	{ ARM64_INS_SQSHRUN, "sqshrun" },
	{ ARM64_INS_SQSHRUN2, "sqshrun2" },
	{ ARM64_INS_SQSUB, "sqsub" },
	{ ARM64_INS_SQXTN2, "sqxtn2" },
	{ ARM64_INS_SQXTN, "sqxtn" },
	{ ARM64_INS_SQXTUN2, "sqxtun2" },
	{ ARM64_INS_SQXTUN, "sqxtun" },
	{ ARM64_INS_SRHADD, "srhadd" },
	{ ARM64_INS_SRI, "sri" },
	{ ARM64_INS_SRSHL, "srshl" },
	{ ARM64_INS_SRSHR, "srshr" },
	{ ARM64_INS_SRSRA, "srsra" },
	{ ARM64_INS_SSHLL2, "sshll2" },
	{ ARM64_INS_SSHLL, "sshll" },
	{ ARM64_INS_SSHL, "sshl" },
	{ ARM64_INS_SSHR, "sshr" },
	{ ARM64_INS_SSRA, "ssra" },
	{ ARM64_INS_SSUBL2, "ssubl2" },
	{ ARM64_INS_SSUBL, "ssubl" },
	{ ARM64_INS_SSUBW2, "ssubw2" },
	{ ARM64_INS_SSUBW, "ssubw" },
	{ ARM64_INS_ST1, "st1" },
	{ ARM64_INS_ST2, "st2" },
	{ ARM64_INS_ST3, "st3" },
	{ ARM64_INS_ST4, "st4" },
	{ ARM64_INS_STLRB, "stlrb" },
	{ ARM64_INS_STLRH, "stlrh" },
	{ ARM64_INS_STLR, "stlr" },
	{ ARM64_INS_STLXP, "stlxp" },
	{ ARM64_INS_STLXRB, "stlxrb" },
	{ ARM64_INS_STLXRH, "stlxrh" },
	{ ARM64_INS_STLXR, "stlxr" },
	{ ARM64_INS_STNP, "stnp" },
	{ ARM64_INS_STP, "stp" },
	{ ARM64_INS_STRB, "strb" },
	{ ARM64_INS_STR, "str" },
	{ ARM64_INS_STRH, "strh" },
	{ ARM64_INS_STTRB, "sttrb" },
	{ ARM64_INS_STTRH, "sttrh" },
	{ ARM64_INS_STTR, "sttr" },
	{ ARM64_INS_STURB, "sturb" },
	{ ARM64_INS_STUR, "stur" },
	{ ARM64_INS_STURH, "sturh" },
	{ ARM64_INS_STXP, "stxp" },
	{ ARM64_INS_STXRB, "stxrb" },
	{ ARM64_INS_STXRH, "stxrh" },
	{ ARM64_INS_STXR, "stxr" },
	{ ARM64_INS_SUBHN, "subhn" },
	{ ARM64_INS_SUBHN2, "subhn2" },
	{ ARM64_INS_SUB, "sub" },
	{ ARM64_INS_SUQADD, "suqadd" },
	{ ARM64_INS_SVC, "svc" },
	{ ARM64_INS_SYSL, "sysl" },
	{ ARM64_INS_SYS, "sys" },
	{ ARM64_INS_TBL, "tbl" },
	{ ARM64_INS_TBNZ, "tbnz" },
	{ ARM64_INS_TBX, "tbx" },
	{ ARM64_INS_TBZ, "tbz" },
	{ ARM64_INS_TRN1, "trn1" },
	{ ARM64_INS_TRN2, "trn2" },
	{ ARM64_INS_UABAL2, "uabal2" },
	{ ARM64_INS_UABAL, "uabal" },
	{ ARM64_INS_UABA, "uaba" },
	{ ARM64_INS_UABDL2, "uabdl2" },
	{ ARM64_INS_UABDL, "uabdl" },
	{ ARM64_INS_UABD, "uabd" },
	{ ARM64_INS_UADALP, "uadalp" },
	{ ARM64_INS_UADDLP, "uaddlp" },
	{ ARM64_INS_UADDLV, "uaddlv" },
	{ ARM64_INS_UADDL2, "uaddl2" },
	{ ARM64_INS_UADDL, "uaddl" },
	{ ARM64_INS_UADDW2, "uaddw2" },
	{ ARM64_INS_UADDW, "uaddw" },
	{ ARM64_INS_UBFM, "ubfm" },
	{ ARM64_INS_UCVTF, "ucvtf" },
	{ ARM64_INS_UDIV, "udiv" },
	{ ARM64_INS_UHADD, "uhadd" },
	{ ARM64_INS_UHSUB, "uhsub" },
	{ ARM64_INS_UMADDL, "umaddl" },
	{ ARM64_INS_UMAXP, "umaxp" },
	{ ARM64_INS_UMAXV, "umaxv" },
	{ ARM64_INS_UMAX, "umax" },
	{ ARM64_INS_UMINP, "uminp" },
	{ ARM64_INS_UMINV, "uminv" },
	{ ARM64_INS_UMIN, "umin" },
	{ ARM64_INS_UMLAL2, "umlal2" },
	{ ARM64_INS_UMLAL, "umlal" },
	{ ARM64_INS_UMLSL2, "umlsl2" },
	{ ARM64_INS_UMLSL, "umlsl" },
	{ ARM64_INS_UMOV, "umov" },
	{ ARM64_INS_UMSUBL, "umsubl" },
	{ ARM64_INS_UMULH, "umulh" },
	{ ARM64_INS_UMULL2, "umull2" },
	{ ARM64_INS_UMULL, "umull" },
	{ ARM64_INS_UQADD, "uqadd" },
	{ ARM64_INS_UQRSHL, "uqrshl" },
	{ ARM64_INS_UQRSHRN, "uqrshrn" },
	{ ARM64_INS_UQRSHRN2, "uqrshrn2" },
	{ ARM64_INS_UQSHL, "uqshl" },
	{ ARM64_INS_UQSHRN, "uqshrn" },
	{ ARM64_INS_UQSHRN2, "uqshrn2" },
	{ ARM64_INS_UQSUB, "uqsub" },
	{ ARM64_INS_UQXTN2, "uqxtn2" },
	{ ARM64_INS_UQXTN, "uqxtn" },
	{ ARM64_INS_URECPE, "urecpe" },
	{ ARM64_INS_URHADD, "urhadd" },
	{ ARM64_INS_URSHL, "urshl" },
	{ ARM64_INS_URSHR, "urshr" },
	{ ARM64_INS_URSQRTE, "ursqrte" },
	{ ARM64_INS_URSRA, "ursra" },
	{ ARM64_INS_USHLL2, "ushll2" },
	{ ARM64_INS_USHLL, "ushll" },
	{ ARM64_INS_USHL, "ushl" },
	{ ARM64_INS_USHR, "ushr" },
	{ ARM64_INS_USQADD, "usqadd" },
	{ ARM64_INS_USRA, "usra" },
	{ ARM64_INS_USUBL2, "usubl2" },
	{ ARM64_INS_USUBL, "usubl" },
	{ ARM64_INS_USUBW2, "usubw2" },
	{ ARM64_INS_USUBW, "usubw" },
	{ ARM64_INS_UZP1, "uzp1" },
	{ ARM64_INS_UZP2, "uzp2" },
	{ ARM64_INS_XTN2, "xtn2" },
	{ ARM64_INS_XTN, "xtn" },
	{ ARM64_INS_ZIP1, "zip1" },
	{ ARM64_INS_ZIP2, "zip2" },
};

// map *S & alias instructions back to original id
static name_map alias_insn_name_maps[] = {
	{ ARM64_INS_ADC, "adcs" },
	{ ARM64_INS_AND, "ands" },
	{ ARM64_INS_ADD, "adds" },
	{ ARM64_INS_BIC, "bics" },
	{ ARM64_INS_SBC, "sbcs" },
	{ ARM64_INS_SUB, "subs" },

	// alias insn
	{ ARM64_INS_MNEG, "mneg" },
	{ ARM64_INS_UMNEGL, "umnegl" },
	{ ARM64_INS_SMNEGL, "smnegl" },
	{ ARM64_INS_NOP, "nop" },
	{ ARM64_INS_YIELD, "yield" },
	{ ARM64_INS_WFE, "wfe" },
	{ ARM64_INS_WFI, "wfi" },
	{ ARM64_INS_SEV, "sev" },
	{ ARM64_INS_SEVL, "sevl" },
	{ ARM64_INS_NGC, "ngc" },
	{ ARM64_INS_NGCS, "ngcs" },
	{ ARM64_INS_NEGS, "negs" },

	{ ARM64_INS_SBFIZ, "sbfiz" },
	{ ARM64_INS_UBFIZ, "ubfiz" },
	{ ARM64_INS_SBFX, "sbfx" },
	{ ARM64_INS_UBFX, "ubfx" },
	{ ARM64_INS_BFI, "bfi" },
	{ ARM64_INS_BFXIL, "bfxil" },
	{ ARM64_INS_CMN, "cmn" },
	{ ARM64_INS_MVN, "mvn" },
	{ ARM64_INS_TST, "tst" },
	{ ARM64_INS_CSET, "cset" },
	{ ARM64_INS_CINC, "cinc" },
	{ ARM64_INS_CSETM, "csetm" },
	{ ARM64_INS_CINV, "cinv" },
	{ ARM64_INS_CNEG, "cneg" },
	{ ARM64_INS_SXTB, "sxtb" },
	{ ARM64_INS_SXTH, "sxth" },
	{ ARM64_INS_SXTW, "sxtw" },
	{ ARM64_INS_CMP, "cmp" },
	{ ARM64_INS_UXTB, "uxtb" },
	{ ARM64_INS_UXTH, "uxth" },
	{ ARM64_INS_UXTW, "uxtw" },

	{ ARM64_INS_IC, "ic" },
	{ ARM64_INS_DC, "dc" },
	{ ARM64_INS_AT, "at" },
	{ ARM64_INS_TLBI, "tlbi" },
};

const char *AArch64_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= ARM64_INS_ENDING)
		return NULL;

	if (id < ARR_SIZE(insn_name_maps))
		return insn_name_maps[id].name;

	// then find alias insn
	for (i = 0; i < ARR_SIZE(alias_insn_name_maps); i++) {
		if (alias_insn_name_maps[i].id == id)
			return alias_insn_name_maps[i].name;
	}

	// not found
	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static name_map group_name_maps[] = {
	// generic groups
	{ ARM64_GRP_INVALID, NULL },
	{ ARM64_GRP_JUMP, "jump" },

	// architecture-specific groups
	{ ARM64_GRP_CRYPTO, "crypto" },
	{ ARM64_GRP_FPARMV8, "fparmv8" },
	{ ARM64_GRP_NEON, "neon" },
	{ ARM64_GRP_CRC, "crc" },

};
#endif

const char *AArch64_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= ARM64_GRP_ENDING || (id > ARM64_GRP_JUMP && id < ARM64_GRP_CRYPTO))
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
arm64_reg AArch64_map_insn(const char *name)
{
	// NOTE: skip first NULL name in insn_name_maps
	int i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	if (i == -1)
		// try again with 'special' insn that is not available in insn_name_maps
		i = name2id(alias_insn_name_maps, ARR_SIZE(alias_insn_name_maps), name);

	return (i != -1)? i : ARM64_REG_INVALID;
}

// map internal raw vregister to 'public' register
arm64_reg AArch64_map_vregister(unsigned int r)
{
	// for some reasons different Arm64 can map different register number to
	// the same register. this function handles the issue for exposing Mips
	// operands by mapping internal registers to 'public' register.
	unsigned int map[] = { 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, ARM64_REG_V0,
		ARM64_REG_V1, ARM64_REG_V2, ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5,
		ARM64_REG_V6, ARM64_REG_V7, ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10,
		ARM64_REG_V11, ARM64_REG_V12, ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15,
		ARM64_REG_V16, ARM64_REG_V17, ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20,
		ARM64_REG_V21, ARM64_REG_V22, ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25,
		ARM64_REG_V26, ARM64_REG_V27, ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30,
		ARM64_REG_V31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, ARM64_REG_V0, ARM64_REG_V1,
		ARM64_REG_V2, ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5, ARM64_REG_V6,
		ARM64_REG_V7, ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10, ARM64_REG_V11,
		ARM64_REG_V12, ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15, ARM64_REG_V16,
		ARM64_REG_V17, ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20, ARM64_REG_V21,
		ARM64_REG_V22, ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25, ARM64_REG_V26,
		ARM64_REG_V27, ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30, ARM64_REG_V31,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, 0, 0, 0,
		0, 0, ARM64_REG_V0, ARM64_REG_V1, ARM64_REG_V2,
		ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5, ARM64_REG_V6, ARM64_REG_V7,
		ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10, ARM64_REG_V11, ARM64_REG_V12,
		ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15, ARM64_REG_V16, ARM64_REG_V17,
		ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20, ARM64_REG_V21, ARM64_REG_V22,
		ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25, ARM64_REG_V26, ARM64_REG_V27,
		ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30, ARM64_REG_V31, ARM64_REG_V0,
		ARM64_REG_V1, ARM64_REG_V2, ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5,
		ARM64_REG_V6, ARM64_REG_V7, ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10,
		ARM64_REG_V11, ARM64_REG_V12, ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15,
		ARM64_REG_V16, ARM64_REG_V17, ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20,
		ARM64_REG_V21, ARM64_REG_V22, ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25,
		ARM64_REG_V26, ARM64_REG_V27, ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30,
		ARM64_REG_V31, ARM64_REG_V0, ARM64_REG_V1, ARM64_REG_V2, ARM64_REG_V3,
		ARM64_REG_V4, ARM64_REG_V5, ARM64_REG_V6, ARM64_REG_V7, ARM64_REG_V8,
		ARM64_REG_V9, ARM64_REG_V10, ARM64_REG_V11, ARM64_REG_V12, ARM64_REG_V13,
		ARM64_REG_V14, ARM64_REG_V15, ARM64_REG_V16, ARM64_REG_V17, ARM64_REG_V18,
		ARM64_REG_V19, ARM64_REG_V20, ARM64_REG_V21, ARM64_REG_V22, ARM64_REG_V23,
		ARM64_REG_V24, ARM64_REG_V25, ARM64_REG_V26, ARM64_REG_V27, ARM64_REG_V28,
		ARM64_REG_V29, ARM64_REG_V30, ARM64_REG_V31, ARM64_REG_V0, ARM64_REG_V1,
		ARM64_REG_V2, ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5, ARM64_REG_V6,
		ARM64_REG_V7, ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10, ARM64_REG_V11,
		ARM64_REG_V12, ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15, ARM64_REG_V16,
		ARM64_REG_V17, ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20, ARM64_REG_V21,
		ARM64_REG_V22, ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25, ARM64_REG_V26,
		ARM64_REG_V27, ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30, ARM64_REG_V31,
		ARM64_REG_V0, ARM64_REG_V1, ARM64_REG_V2, ARM64_REG_V3, ARM64_REG_V4,
		ARM64_REG_V5, ARM64_REG_V6, ARM64_REG_V7, ARM64_REG_V8, ARM64_REG_V9,
		ARM64_REG_V10, ARM64_REG_V11, ARM64_REG_V12, ARM64_REG_V13, ARM64_REG_V14,
		ARM64_REG_V15, ARM64_REG_V16, ARM64_REG_V17, ARM64_REG_V18, ARM64_REG_V19,
		ARM64_REG_V20, ARM64_REG_V21, ARM64_REG_V22, ARM64_REG_V23, ARM64_REG_V24,
		ARM64_REG_V25, ARM64_REG_V26, ARM64_REG_V27, ARM64_REG_V28, ARM64_REG_V29,
		ARM64_REG_V30, ARM64_REG_V31, ARM64_REG_V0, ARM64_REG_V1, ARM64_REG_V2,
		ARM64_REG_V3, ARM64_REG_V4, ARM64_REG_V5, ARM64_REG_V6, ARM64_REG_V7,
		ARM64_REG_V8, ARM64_REG_V9, ARM64_REG_V10, ARM64_REG_V11, ARM64_REG_V12,
		ARM64_REG_V13, ARM64_REG_V14, ARM64_REG_V15, ARM64_REG_V16, ARM64_REG_V17,
		ARM64_REG_V18, ARM64_REG_V19, ARM64_REG_V20, ARM64_REG_V21, ARM64_REG_V22,
		ARM64_REG_V23, ARM64_REG_V24, ARM64_REG_V25, ARM64_REG_V26, ARM64_REG_V27,
		ARM64_REG_V28, ARM64_REG_V29, ARM64_REG_V30, ARM64_REG_V31, };

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

void arm64_op_addVectorArrSpecifier(MCInst * MI, int sp)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count - 1].vas = sp;
	}
}

void arm64_op_addVectorElementSizeSpecifier(MCInst * MI, int sp)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count - 1].vess = sp;
	}
}

void arm64_op_addFP(MCInst *MI, float fp)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].type = ARM64_OP_FP;
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].fp = fp;
		MI->flat_insn->detail->arm64.op_count++;
	}
}

void arm64_op_addImm(MCInst *MI, int64_t imm)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].type = ARM64_OP_IMM;
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].imm = (int)imm;
		MI->flat_insn->detail->arm64.op_count++;
	}
}

#endif
