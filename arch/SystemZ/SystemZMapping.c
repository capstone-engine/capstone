/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_SYSZ

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "SystemZMapping.h"

#define GET_INSTRINFO_ENUM
#include "SystemZGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ SYSZ_REG_INVALID, NULL },

	{ SYSZ_REG_0, "0"},
	{ SYSZ_REG_1, "1"},
	{ SYSZ_REG_2, "2"},
	{ SYSZ_REG_3, "3"},
	{ SYSZ_REG_4, "4"},
	{ SYSZ_REG_5, "5"},
	{ SYSZ_REG_6, "6"},
	{ SYSZ_REG_7, "7"},
	{ SYSZ_REG_8, "8"},
	{ SYSZ_REG_9, "9"},
	{ SYSZ_REG_10, "10"},
	{ SYSZ_REG_11, "11"},
	{ SYSZ_REG_12, "12"},
	{ SYSZ_REG_13, "13"},
	{ SYSZ_REG_14, "14"},
	{ SYSZ_REG_15, "15"},
	{ SYSZ_REG_CC, "cc"},
	{ SYSZ_REG_F0, "f0"},
	{ SYSZ_REG_F1, "f1"},
	{ SYSZ_REG_F2, "f2"},
	{ SYSZ_REG_F3, "f3"},
	{ SYSZ_REG_F4, "f4"},
	{ SYSZ_REG_F5, "f5"},
	{ SYSZ_REG_F6, "f6"},
	{ SYSZ_REG_F7, "f7"},
	{ SYSZ_REG_F8, "f8"},
	{ SYSZ_REG_F9, "f9"},
	{ SYSZ_REG_F10, "f10"},
	{ SYSZ_REG_F11, "f11"},
	{ SYSZ_REG_F12, "f12"},
	{ SYSZ_REG_F13, "f13"},
	{ SYSZ_REG_F14, "f14"},
	{ SYSZ_REG_F15, "f15"},
	{ SYSZ_REG_R0L, "r0l"},
};
#endif

const char *SystemZ_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= SYSZ_REG_ENDING)
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
		SystemZ_A, SYSZ_INS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ADB, SYSZ_INS_ADB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ADBR, SYSZ_INS_ADBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AEB, SYSZ_INS_AEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AEBR, SYSZ_INS_AEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AFI, SYSZ_INS_AFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AG, SYSZ_INS_AG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGF, SYSZ_INS_AGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGFI, SYSZ_INS_AGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGFR, SYSZ_INS_AGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGHI, SYSZ_INS_AGHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGHIK, SYSZ_INS_AGHIK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGR, SYSZ_INS_AGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGRK, SYSZ_INS_AGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AGSI, SYSZ_INS_AGSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AH, SYSZ_INS_AH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AHI, SYSZ_INS_AHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AHIK, SYSZ_INS_AHIK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AHY, SYSZ_INS_AHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AIH, SYSZ_INS_AIH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AL, SYSZ_INS_AL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALC, SYSZ_INS_ALC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALCG, SYSZ_INS_ALCG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALCGR, SYSZ_INS_ALCGR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALCR, SYSZ_INS_ALCR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALFI, SYSZ_INS_ALFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALG, SYSZ_INS_ALG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGF, SYSZ_INS_ALGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGFI, SYSZ_INS_ALGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGFR, SYSZ_INS_ALGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGHSIK, SYSZ_INS_ALGHSIK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGR, SYSZ_INS_ALGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALGRK, SYSZ_INS_ALGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALHSIK, SYSZ_INS_ALHSIK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALR, SYSZ_INS_ALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALRK, SYSZ_INS_ALRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_ALY, SYSZ_INS_ALY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AR, SYSZ_INS_AR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ARK, SYSZ_INS_ARK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_ASI, SYSZ_INS_ASI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AXBR, SYSZ_INS_AXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AY, SYSZ_INS_AY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmBCR, SYSZ_INS_BCR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmBRC, SYSZ_INS_BRC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmBRCL, SYSZ_INS_BRCL,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCGIJ, SYSZ_INS_CGIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCGRJ, SYSZ_INS_CGRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCIJ, SYSZ_INS_CIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCLGIJ, SYSZ_INS_CLGIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCLGRJ, SYSZ_INS_CLGRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCLIJ, SYSZ_INS_CLIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCLRJ, SYSZ_INS_CLRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmCRJ, SYSZ_INS_CRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_AsmEBR, SYSZ_INS_BER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmEJ, SYSZ_INS_JE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmEJG, SYSZ_INS_JGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmELOC, SYSZ_INS_LOCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmELOCG, SYSZ_INS_LOCGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmELOCGR, SYSZ_INS_LOCGRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmELOCR, SYSZ_INS_LOCRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmESTOC, SYSZ_INS_STOCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmESTOCG, SYSZ_INS_STOCGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHBR, SYSZ_INS_BHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHEBR, SYSZ_INS_BHER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHEJ, SYSZ_INS_JHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHEJG, SYSZ_INS_JGHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHELOC, SYSZ_INS_LOCHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHELOCG, SYSZ_INS_LOCGHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHELOCGR, SYSZ_INS_LOCGRHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHELOCR, SYSZ_INS_LOCRHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHESTOC, SYSZ_INS_STOCHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHESTOCG, SYSZ_INS_STOCGHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHJ, SYSZ_INS_JH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHJG, SYSZ_INS_JGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHLOC, SYSZ_INS_LOCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHLOCG, SYSZ_INS_LOCGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHLOCGR, SYSZ_INS_LOCGRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHLOCR, SYSZ_INS_LOCRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHSTOC, SYSZ_INS_STOCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmHSTOCG, SYSZ_INS_STOCGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCGI, SYSZ_INS_CGIJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCGR, SYSZ_INS_CGRJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCI, SYSZ_INS_CIJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCLGI, SYSZ_INS_CLGIJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCLGR, SYSZ_INS_CLGRJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCLI, SYSZ_INS_CLIJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCLR, SYSZ_INS_CLRJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJEAltCR, SYSZ_INS_CRJNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECGI, SYSZ_INS_CGIJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECGR, SYSZ_INS_CGRJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECI, SYSZ_INS_CIJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECLGI, SYSZ_INS_CLGIJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECLGR, SYSZ_INS_CLGRJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECLI, SYSZ_INS_CLIJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECLR, SYSZ_INS_CLRJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJECR, SYSZ_INS_CRJE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCGI, SYSZ_INS_CGIJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCGR, SYSZ_INS_CGRJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCI, SYSZ_INS_CIJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCLGI, SYSZ_INS_CLGIJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCLGR, SYSZ_INS_CLGRJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCLI, SYSZ_INS_CLIJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCLR, SYSZ_INS_CLRJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHAltCR, SYSZ_INS_CRJNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCGI, SYSZ_INS_CGIJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCGR, SYSZ_INS_CGRJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCI, SYSZ_INS_CIJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCLGI, SYSZ_INS_CLGIJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCLGR, SYSZ_INS_CLGRJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCLI, SYSZ_INS_CLIJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCLR, SYSZ_INS_CLRJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHCR, SYSZ_INS_CRJH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCGI, SYSZ_INS_CGIJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCGR, SYSZ_INS_CGRJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCI, SYSZ_INS_CIJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCLGI, SYSZ_INS_CLGIJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCLGR, SYSZ_INS_CLGRJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCLI, SYSZ_INS_CLIJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCLR, SYSZ_INS_CLRJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHEAltCR, SYSZ_INS_CRJNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECGI, SYSZ_INS_CGIJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECGR, SYSZ_INS_CGRJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECI, SYSZ_INS_CIJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECLGI, SYSZ_INS_CLGIJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECLGR, SYSZ_INS_CLGRJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECLI, SYSZ_INS_CLIJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECLR, SYSZ_INS_CLRJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJHECR, SYSZ_INS_CRJHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCGI, SYSZ_INS_CGIJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCGR, SYSZ_INS_CGRJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCI, SYSZ_INS_CIJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCLGI, SYSZ_INS_CLGIJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCLGR, SYSZ_INS_CLGRJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCLI, SYSZ_INS_CLIJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCLR, SYSZ_INS_CLRJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLAltCR, SYSZ_INS_CRJNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCGI, SYSZ_INS_CGIJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCGR, SYSZ_INS_CGRJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCI, SYSZ_INS_CIJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCLGI, SYSZ_INS_CLGIJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCLGR, SYSZ_INS_CLGRJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCLI, SYSZ_INS_CLIJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCLR, SYSZ_INS_CLRJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLCR, SYSZ_INS_CRJL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCGI, SYSZ_INS_CGIJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCGR, SYSZ_INS_CGRJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCI, SYSZ_INS_CIJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCLGI, SYSZ_INS_CLGIJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCLGR, SYSZ_INS_CLGRJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCLI, SYSZ_INS_CLIJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCLR, SYSZ_INS_CLRJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLEAltCR, SYSZ_INS_CRJNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECGI, SYSZ_INS_CGIJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECGR, SYSZ_INS_CGRJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECI, SYSZ_INS_CIJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECLGI, SYSZ_INS_CLGIJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECLGR, SYSZ_INS_CLGRJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECLI, SYSZ_INS_CLIJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECLR, SYSZ_INS_CLRJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLECR, SYSZ_INS_CRJLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCGI, SYSZ_INS_CGIJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCGR, SYSZ_INS_CGRJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCI, SYSZ_INS_CIJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCLGI, SYSZ_INS_CLGIJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCLGR, SYSZ_INS_CLGRJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCLI, SYSZ_INS_CLIJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCLR, SYSZ_INS_CLRJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHAltCR, SYSZ_INS_CRJNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCGI, SYSZ_INS_CGIJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCGR, SYSZ_INS_CGRJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCI, SYSZ_INS_CIJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCLGI, SYSZ_INS_CLGIJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCLGR, SYSZ_INS_CLGRJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCLI, SYSZ_INS_CLIJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCLR, SYSZ_INS_CLRJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmJLHCR, SYSZ_INS_CRJLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLBR, SYSZ_INS_BLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLEBR, SYSZ_INS_BLER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLEJ, SYSZ_INS_JLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLEJG, SYSZ_INS_JGLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLELOC, SYSZ_INS_LOCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLELOCG, SYSZ_INS_LOCGLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLELOCGR, SYSZ_INS_LOCGRLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLELOCR, SYSZ_INS_LOCRLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLESTOC, SYSZ_INS_STOCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLESTOCG, SYSZ_INS_STOCGLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHBR, SYSZ_INS_BLHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHJ, SYSZ_INS_JLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHJG, SYSZ_INS_JGLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHLOC, SYSZ_INS_LOCLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHLOCG, SYSZ_INS_LOCGLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHLOCGR, SYSZ_INS_LOCGRLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHLOCR, SYSZ_INS_LOCRLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHSTOC, SYSZ_INS_STOCLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLHSTOCG, SYSZ_INS_STOCGLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLJ, SYSZ_INS_JL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLJG, SYSZ_INS_JGL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLLOC, SYSZ_INS_LOCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLLOCG, SYSZ_INS_LOCGL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLLOCGR, SYSZ_INS_LOCGRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLLOCR, SYSZ_INS_LOCRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLOC, SYSZ_INS_LOC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLOCG, SYSZ_INS_LOCG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLOCGR, SYSZ_INS_LOCGR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLOCR, SYSZ_INS_LOCR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLSTOC, SYSZ_INS_STOCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmLSTOCG, SYSZ_INS_STOCGL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNEBR, SYSZ_INS_BNER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNEJ, SYSZ_INS_JNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNEJG, SYSZ_INS_JGNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNELOC, SYSZ_INS_LOCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNELOCG, SYSZ_INS_LOCGNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNELOCGR, SYSZ_INS_LOCGRNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNELOCR, SYSZ_INS_LOCRNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNESTOC, SYSZ_INS_STOCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNESTOCG, SYSZ_INS_STOCGNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHBR, SYSZ_INS_BNHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHEBR, SYSZ_INS_BNHER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHEJ, SYSZ_INS_JNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHEJG, SYSZ_INS_JGNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHELOC, SYSZ_INS_LOCNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHELOCG, SYSZ_INS_LOCGNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHELOCGR, SYSZ_INS_LOCGRNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHELOCR, SYSZ_INS_LOCRNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHESTOC, SYSZ_INS_STOCNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHESTOCG, SYSZ_INS_STOCGNHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHJ, SYSZ_INS_JNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHJG, SYSZ_INS_JGNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHLOC, SYSZ_INS_LOCNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHLOCG, SYSZ_INS_LOCGNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHLOCGR, SYSZ_INS_LOCGRNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHLOCR, SYSZ_INS_LOCRNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHSTOC, SYSZ_INS_STOCNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNHSTOCG, SYSZ_INS_STOCGNH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLBR, SYSZ_INS_BNLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLEBR, SYSZ_INS_BNLER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLEJ, SYSZ_INS_JNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLEJG, SYSZ_INS_JGNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLELOC, SYSZ_INS_LOCNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLELOCG, SYSZ_INS_LOCGNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLELOCGR, SYSZ_INS_LOCGRNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLELOCR, SYSZ_INS_LOCRNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLESTOC, SYSZ_INS_STOCNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLESTOCG, SYSZ_INS_STOCGNLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHBR, SYSZ_INS_BNLHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHJ, SYSZ_INS_JNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHJG, SYSZ_INS_JGNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHLOC, SYSZ_INS_LOCNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHLOCG, SYSZ_INS_LOCGNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHLOCGR, SYSZ_INS_LOCGRNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHLOCR, SYSZ_INS_LOCRNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHSTOC, SYSZ_INS_STOCNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLHSTOCG, SYSZ_INS_STOCGNLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLJ, SYSZ_INS_JNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLJG, SYSZ_INS_JGNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLLOC, SYSZ_INS_LOCNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLLOCG, SYSZ_INS_LOCGNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLLOCGR, SYSZ_INS_LOCGRNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLLOCR, SYSZ_INS_LOCRNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLSTOC, SYSZ_INS_STOCNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNLSTOCG, SYSZ_INS_STOCGNL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOBR, SYSZ_INS_BNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOJ, SYSZ_INS_JNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOJG, SYSZ_INS_JGNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOLOC, SYSZ_INS_LOCNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOLOCG, SYSZ_INS_LOCGNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOLOCGR, SYSZ_INS_LOCGRNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOLOCR, SYSZ_INS_LOCRNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOSTOC, SYSZ_INS_STOCNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmNOSTOCG, SYSZ_INS_STOCGNO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOBR, SYSZ_INS_BOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOJ, SYSZ_INS_JO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOJG, SYSZ_INS_JGO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOLOC, SYSZ_INS_LOCO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOLOCG, SYSZ_INS_LOCGO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOLOCGR, SYSZ_INS_LOCGRO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOLOCR, SYSZ_INS_LOCRO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOSTOC, SYSZ_INS_STOCO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmOSTOCG, SYSZ_INS_STOCGO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmSTOC, SYSZ_INS_STOC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_AsmSTOCG, SYSZ_INS_STOCG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_BASR, SYSZ_INS_BASR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_BR, SYSZ_INS_BR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		SystemZ_BRAS, SYSZ_INS_BRAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_BRASL, SYSZ_INS_BRASL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_BRC, SYSZ_INS_J,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_BRCL, SYSZ_INS_JG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_BRCT, SYSZ_INS_BRCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_BRCTG, SYSZ_INS_BRCTG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_C, SYSZ_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDB, SYSZ_INS_CDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDBR, SYSZ_INS_CDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDFBR, SYSZ_INS_CDFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDGBR, SYSZ_INS_CDGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDLFBR, SYSZ_INS_CDLFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CDLGBR, SYSZ_INS_CDLGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CEB, SYSZ_INS_CEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CEBR, SYSZ_INS_CEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CEFBR, SYSZ_INS_CEFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CEGBR, SYSZ_INS_CEGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CELFBR, SYSZ_INS_CELFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CELGBR, SYSZ_INS_CELGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CFDBR, SYSZ_INS_CFDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CFEBR, SYSZ_INS_CFEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CFI, SYSZ_INS_CFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CFXBR, SYSZ_INS_CFXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CG, SYSZ_INS_CG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGDBR, SYSZ_INS_CGDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGEBR, SYSZ_INS_CGEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGF, SYSZ_INS_CGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGFI, SYSZ_INS_CGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGFR, SYSZ_INS_CGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGFRL, SYSZ_INS_CGFRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGH, SYSZ_INS_CGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGHI, SYSZ_INS_CGHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGHRL, SYSZ_INS_CGHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGHSI, SYSZ_INS_CGHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGIJ, SYSZ_INS_CGIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CGR, SYSZ_INS_CGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGRJ, SYSZ_INS_CGRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CGRL, SYSZ_INS_CGRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CGXBR, SYSZ_INS_CGXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CH, SYSZ_INS_CH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHF, SYSZ_INS_CHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHHSI, SYSZ_INS_CHHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHI, SYSZ_INS_CHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHRL, SYSZ_INS_CHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHSI, SYSZ_INS_CHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CHY, SYSZ_INS_CHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CIH, SYSZ_INS_CIH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CIJ, SYSZ_INS_CIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CL, SYSZ_INS_CL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLC, SYSZ_INS_CLC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLFDBR, SYSZ_INS_CLFDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLFEBR, SYSZ_INS_CLFEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLFHSI, SYSZ_INS_CLFHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLFI, SYSZ_INS_CLFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLFXBR, SYSZ_INS_CLFXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLG, SYSZ_INS_CLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGDBR, SYSZ_INS_CLGDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGEBR, SYSZ_INS_CLGEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGF, SYSZ_INS_CLGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGFI, SYSZ_INS_CLGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGFR, SYSZ_INS_CLGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGFRL, SYSZ_INS_CLGFRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGHRL, SYSZ_INS_CLGHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGHSI, SYSZ_INS_CLGHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGIJ, SYSZ_INS_CLGIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CLGR, SYSZ_INS_CLGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGRJ, SYSZ_INS_CLGRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CLGRL, SYSZ_INS_CLGRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLGXBR, SYSZ_INS_CLGXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLHF, SYSZ_INS_CLHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLHHSI, SYSZ_INS_CLHHSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLHRL, SYSZ_INS_CLHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLI, SYSZ_INS_CLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLIH, SYSZ_INS_CLIH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLIJ, SYSZ_INS_CLIJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CLIY, SYSZ_INS_CLIY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLR, SYSZ_INS_CLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLRJ, SYSZ_INS_CLRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CLRL, SYSZ_INS_CLRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLST, SYSZ_INS_CLST,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_R0L, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CLY, SYSZ_INS_CLY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CPSDRdd, SYSZ_INS_CPSDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CPSDRds, SYSZ_INS_CPSDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CPSDRsd, SYSZ_INS_CPSDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CPSDRss, SYSZ_INS_CPSDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CR, SYSZ_INS_CR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CRJ, SYSZ_INS_CRJ,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_CRL, SYSZ_INS_CRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CS, SYSZ_INS_CS,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CSG, SYSZ_INS_CSG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CSY, SYSZ_INS_CSY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CXBR, SYSZ_INS_CXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CXFBR, SYSZ_INS_CXFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CXGBR, SYSZ_INS_CXGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_CXLFBR, SYSZ_INS_CXLFBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CXLGBR, SYSZ_INS_CXLGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_CY, SYSZ_INS_CY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DDB, SYSZ_INS_DDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DDBR, SYSZ_INS_DDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DEB, SYSZ_INS_DEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DEBR, SYSZ_INS_DEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DL, SYSZ_INS_DL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DLG, SYSZ_INS_DLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DLGR, SYSZ_INS_DLGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DLR, SYSZ_INS_DLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DSG, SYSZ_INS_DSG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DSGF, SYSZ_INS_DSGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DSGFR, SYSZ_INS_DSGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DSGR, SYSZ_INS_DSGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_DXBR, SYSZ_INS_DXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_EAR, SYSZ_INS_EAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIDBR, SYSZ_INS_FIDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIDBRA, SYSZ_INS_FIDBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIEBR, SYSZ_INS_FIEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIEBRA, SYSZ_INS_FIEBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIXBR, SYSZ_INS_FIXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_FIXBRA, SYSZ_INS_FIXBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_FLOGR, SYSZ_INS_FLOGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IC, SYSZ_INS_IC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IC32, SYSZ_INS_IC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IC32Y, SYSZ_INS_ICY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ICY, SYSZ_INS_ICY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IIHF, SYSZ_INS_IIHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IIHH, SYSZ_INS_IIHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IIHL, SYSZ_INS_IIHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IILF, SYSZ_INS_IILF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IILH, SYSZ_INS_IILH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IILL, SYSZ_INS_IILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_IPM, SYSZ_INS_IPM,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_J, SYSZ_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_JG, SYSZ_INS_JG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		SystemZ_L, SYSZ_INS_L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LA, SYSZ_INS_LA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAA, SYSZ_INS_LAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAAG, SYSZ_INS_LAAG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAAL, SYSZ_INS_LAAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAALG, SYSZ_INS_LAALG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAN, SYSZ_INS_LAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LANG, SYSZ_INS_LANG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAO, SYSZ_INS_LAO,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAOG, SYSZ_INS_LAOG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LARL, SYSZ_INS_LARL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAX, SYSZ_INS_LAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAXG, SYSZ_INS_LAXG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_INTERLOCKEDACCESS1, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LAY, SYSZ_INS_LAY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LB, SYSZ_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LBH, SYSZ_INS_LBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LBR, SYSZ_INS_LBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCDBR, SYSZ_INS_LCDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCEBR, SYSZ_INS_LCEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCGFR, SYSZ_INS_LCGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCGR, SYSZ_INS_LCGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCR, SYSZ_INS_LCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LCXBR, SYSZ_INS_LCXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LD, SYSZ_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDEB, SYSZ_INS_LDEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDEBR, SYSZ_INS_LDEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDGR, SYSZ_INS_LDGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDR, SYSZ_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDXBR, SYSZ_INS_LDXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDXBRA, SYSZ_INS_LDXBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LDY, SYSZ_INS_LDY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LE, SYSZ_INS_LE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LEDBR, SYSZ_INS_LEDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LEDBRA, SYSZ_INS_LEDBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LER, SYSZ_INS_LER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LEXBR, SYSZ_INS_LEXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LEXBRA, SYSZ_INS_LEXBRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_FPEXTENSION, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LEY, SYSZ_INS_LEY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LFH, SYSZ_INS_LFH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LG, SYSZ_INS_LG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGB, SYSZ_INS_LGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGBR, SYSZ_INS_LGBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGDR, SYSZ_INS_LGDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGF, SYSZ_INS_LGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGFI, SYSZ_INS_LGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGFR, SYSZ_INS_LGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGFRL, SYSZ_INS_LGFRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGH, SYSZ_INS_LGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGHI, SYSZ_INS_LGHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGHR, SYSZ_INS_LGHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGHRL, SYSZ_INS_LGHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGR, SYSZ_INS_LGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LGRL, SYSZ_INS_LGRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LH, SYSZ_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LHH, SYSZ_INS_LHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LHI, SYSZ_INS_LHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LHR, SYSZ_INS_LHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LHRL, SYSZ_INS_LHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LHY, SYSZ_INS_LHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLC, SYSZ_INS_LLC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLCH, SYSZ_INS_LLCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLCR, SYSZ_INS_LLCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGC, SYSZ_INS_LLGC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGCR, SYSZ_INS_LLGCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGF, SYSZ_INS_LLGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGFR, SYSZ_INS_LLGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGFRL, SYSZ_INS_LLGFRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGH, SYSZ_INS_LLGH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGHR, SYSZ_INS_LLGHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLGHRL, SYSZ_INS_LLGHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLH, SYSZ_INS_LLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLHH, SYSZ_INS_LLHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLHR, SYSZ_INS_LLHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLHRL, SYSZ_INS_LLHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLIHF, SYSZ_INS_LLIHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLIHH, SYSZ_INS_LLIHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLIHL, SYSZ_INS_LLIHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLILF, SYSZ_INS_LLILF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLILH, SYSZ_INS_LLILH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LLILL, SYSZ_INS_LLILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LMG, SYSZ_INS_LMG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNDBR, SYSZ_INS_LNDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNEBR, SYSZ_INS_LNEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNGFR, SYSZ_INS_LNGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNGR, SYSZ_INS_LNGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNR, SYSZ_INS_LNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LNXBR, SYSZ_INS_LNXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LOC, SYSZ_INS_LOC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LOCG, SYSZ_INS_LOCG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LOCGR, SYSZ_INS_LOCGR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LOCR, SYSZ_INS_LOCR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPDBR, SYSZ_INS_LPDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPEBR, SYSZ_INS_LPEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPGFR, SYSZ_INS_LPGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPGR, SYSZ_INS_LPGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPR, SYSZ_INS_LPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LPXBR, SYSZ_INS_LPXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LR, SYSZ_INS_LR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LRL, SYSZ_INS_LRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LRV, SYSZ_INS_LRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LRVG, SYSZ_INS_LRVG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LRVGR, SYSZ_INS_LRVGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LRVR, SYSZ_INS_LRVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LT, SYSZ_INS_LT,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTDBR, SYSZ_INS_LTDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTDBRCompare, SYSZ_INS_LTDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTEBR, SYSZ_INS_LTEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTEBRCompare, SYSZ_INS_LTEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTG, SYSZ_INS_LTG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTGF, SYSZ_INS_LTGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTGFR, SYSZ_INS_LTGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTGR, SYSZ_INS_LTGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTR, SYSZ_INS_LTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTXBR, SYSZ_INS_LTXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LTXBRCompare, SYSZ_INS_LTXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LXDB, SYSZ_INS_LXDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LXDBR, SYSZ_INS_LXDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LXEB, SYSZ_INS_LXEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LXEBR, SYSZ_INS_LXEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LXR, SYSZ_INS_LXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LY, SYSZ_INS_LY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LZDR, SYSZ_INS_LZDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LZER, SYSZ_INS_LZER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_LZXR, SYSZ_INS_LZXR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MADB, SYSZ_INS_MADB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MADBR, SYSZ_INS_MADBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MAEB, SYSZ_INS_MAEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MAEBR, SYSZ_INS_MAEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MDB, SYSZ_INS_MDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MDBR, SYSZ_INS_MDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MDEB, SYSZ_INS_MDEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MDEBR, SYSZ_INS_MDEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MEEB, SYSZ_INS_MEEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MEEBR, SYSZ_INS_MEEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MGHI, SYSZ_INS_MGHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MH, SYSZ_INS_MH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MHI, SYSZ_INS_MHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MHY, SYSZ_INS_MHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MLG, SYSZ_INS_MLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MLGR, SYSZ_INS_MLGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MS, SYSZ_INS_MS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSDB, SYSZ_INS_MSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSDBR, SYSZ_INS_MSDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSEB, SYSZ_INS_MSEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSEBR, SYSZ_INS_MSEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSFI, SYSZ_INS_MSFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSG, SYSZ_INS_MSG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSGF, SYSZ_INS_MSGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSGFI, SYSZ_INS_MSGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSGFR, SYSZ_INS_MSGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSGR, SYSZ_INS_MSGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSR, SYSZ_INS_MSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MSY, SYSZ_INS_MSY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVC, SYSZ_INS_MVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVGHI, SYSZ_INS_MVGHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVHHI, SYSZ_INS_MVHHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVHI, SYSZ_INS_MVHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVI, SYSZ_INS_MVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVIY, SYSZ_INS_MVIY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MVST, SYSZ_INS_MVST,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_R0L, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MXBR, SYSZ_INS_MXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MXDB, SYSZ_INS_MXDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_MXDBR, SYSZ_INS_MXDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_N, SYSZ_INS_N,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NC, SYSZ_INS_NC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NG, SYSZ_INS_NG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NGR, SYSZ_INS_NGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NGRK, SYSZ_INS_NGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_NI, SYSZ_INS_NI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NIHF, SYSZ_INS_NIHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NIHH, SYSZ_INS_NIHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NIHL, SYSZ_INS_NIHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NILF, SYSZ_INS_NILF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NILH, SYSZ_INS_NILH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NILL, SYSZ_INS_NILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NIY, SYSZ_INS_NIY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NR, SYSZ_INS_NR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_NRK, SYSZ_INS_NRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_NY, SYSZ_INS_NY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_O, SYSZ_INS_O,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OC, SYSZ_INS_OC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OG, SYSZ_INS_OG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OGR, SYSZ_INS_OGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OGRK, SYSZ_INS_OGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_OI, SYSZ_INS_OI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OIHF, SYSZ_INS_OIHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OIHH, SYSZ_INS_OIHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OIHL, SYSZ_INS_OIHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OILF, SYSZ_INS_OILF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OILH, SYSZ_INS_OILH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OILL, SYSZ_INS_OILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OIY, SYSZ_INS_OIY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_OR, SYSZ_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ORK, SYSZ_INS_ORK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_OY, SYSZ_INS_OY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_PFD, SYSZ_INS_PFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_PFDRL, SYSZ_INS_PFDRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RISBG, SYSZ_INS_RISBG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RISBG32, SYSZ_INS_RISBG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RISBHG, SYSZ_INS_RISBHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_RISBLG, SYSZ_INS_RISBLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_RLL, SYSZ_INS_RLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RLLG, SYSZ_INS_RLLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RNSBG, SYSZ_INS_RNSBG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ROSBG, SYSZ_INS_ROSBG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_RXSBG, SYSZ_INS_RXSBG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_S, SYSZ_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SDB, SYSZ_INS_SDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SDBR, SYSZ_INS_SDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SEB, SYSZ_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SEBR, SYSZ_INS_SEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SG, SYSZ_INS_SG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SGF, SYSZ_INS_SGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SGFR, SYSZ_INS_SGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SGR, SYSZ_INS_SGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SGRK, SYSZ_INS_SGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SH, SYSZ_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SHY, SYSZ_INS_SHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SL, SYSZ_INS_SL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLB, SYSZ_INS_SLB,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLBG, SYSZ_INS_SLBG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLBR, SYSZ_INS_SLBR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLFI, SYSZ_INS_SLFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLG, SYSZ_INS_SLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGBR, SYSZ_INS_SLBGR,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGF, SYSZ_INS_SLGF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGFI, SYSZ_INS_SLGFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGFR, SYSZ_INS_SLGFR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGR, SYSZ_INS_SLGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLGRK, SYSZ_INS_SLGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLL, SYSZ_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLLG, SYSZ_INS_SLLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLLK, SYSZ_INS_SLLK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLR, SYSZ_INS_SLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLRK, SYSZ_INS_SLRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SLY, SYSZ_INS_SLY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SQDB, SYSZ_INS_SQDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SQDBR, SYSZ_INS_SQDBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SQEB, SYSZ_INS_SQEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SQEBR, SYSZ_INS_SQEBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SQXBR, SYSZ_INS_SQXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SR, SYSZ_INS_SR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRA, SYSZ_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRAG, SYSZ_INS_SRAG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRAK, SYSZ_INS_SRAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRK, SYSZ_INS_SRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRL, SYSZ_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRLG, SYSZ_INS_SRLG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRLK, SYSZ_INS_SRLK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_SRST, SYSZ_INS_SRST,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_R0L, 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_ST, SYSZ_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STC, SYSZ_INS_STC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STCH, SYSZ_INS_STCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_STCY, SYSZ_INS_STCY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STD, SYSZ_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STDY, SYSZ_INS_STDY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STE, SYSZ_INS_STE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STEY, SYSZ_INS_STEY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STFH, SYSZ_INS_STFH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_STG, SYSZ_INS_STG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STGRL, SYSZ_INS_STGRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STH, SYSZ_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STHH, SYSZ_INS_STHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { SYSZ_GRP_HIGHWORD, 0 }, 0, 0
#endif
	},
	{
		SystemZ_STHRL, SYSZ_INS_STHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STHY, SYSZ_INS_STHY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STMG, SYSZ_INS_STMG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STOC, SYSZ_INS_STOC,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_STOCG, SYSZ_INS_STOCG,
#ifndef CAPSTONE_DIET
		{ SYSZ_REG_CC, 0 }, { 0 }, { SYSZ_GRP_LOADSTOREONCOND, 0 }, 0, 0
#endif
	},
	{
		SystemZ_STRL, SYSZ_INS_STRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STRV, SYSZ_INS_STRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STRVG, SYSZ_INS_STRVG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_STY, SYSZ_INS_STY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SXBR, SYSZ_INS_SXBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_SY, SYSZ_INS_SY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TM, SYSZ_INS_TM,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TMHH, SYSZ_INS_TMHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TMHL, SYSZ_INS_TMHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TMLH, SYSZ_INS_TMLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TMLL, SYSZ_INS_TMLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_TMY, SYSZ_INS_TMY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_X, SYSZ_INS_X,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XC, SYSZ_INS_XC,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XG, SYSZ_INS_XG,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XGR, SYSZ_INS_XGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XGRK, SYSZ_INS_XGRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_XI, SYSZ_INS_XI,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XIHF, SYSZ_INS_XIHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XILF, SYSZ_INS_XILF,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XIY, SYSZ_INS_XIY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XR, SYSZ_INS_XR,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
	{
		SystemZ_XRK, SYSZ_INS_XRK,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { SYSZ_GRP_DISTINCTOPS, 0 }, 0, 0
#endif
	},
	{
		SystemZ_XY, SYSZ_INS_XY,
#ifndef CAPSTONE_DIET
		{ 0 }, { SYSZ_REG_CC, 0 }, { 0 }, 0, 0
#endif
	},
};

// given internal insn id, return public instruction info
void SystemZ_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
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
				insn->detail->groups[insn->detail->groups_count] = SYSZ_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[] = {
	{ SYSZ_INS_INVALID, NULL },

	{ SYSZ_INS_A, "a" },
	{ SYSZ_INS_ADB, "adb" },
	{ SYSZ_INS_ADBR, "adbr" },
	{ SYSZ_INS_AEB, "aeb" },
	{ SYSZ_INS_AEBR, "aebr" },
	{ SYSZ_INS_AFI, "afi" },
	{ SYSZ_INS_AG, "ag" },
	{ SYSZ_INS_AGF, "agf" },
	{ SYSZ_INS_AGFI, "agfi" },
	{ SYSZ_INS_AGFR, "agfr" },
	{ SYSZ_INS_AGHI, "aghi" },
	{ SYSZ_INS_AGHIK, "aghik" },
	{ SYSZ_INS_AGR, "agr" },
	{ SYSZ_INS_AGRK, "agrk" },
	{ SYSZ_INS_AGSI, "agsi" },
	{ SYSZ_INS_AH, "ah" },
	{ SYSZ_INS_AHI, "ahi" },
	{ SYSZ_INS_AHIK, "ahik" },
	{ SYSZ_INS_AHY, "ahy" },
	{ SYSZ_INS_AIH, "aih" },
	{ SYSZ_INS_AL, "al" },
	{ SYSZ_INS_ALC, "alc" },
	{ SYSZ_INS_ALCG, "alcg" },
	{ SYSZ_INS_ALCGR, "alcgr" },
	{ SYSZ_INS_ALCR, "alcr" },
	{ SYSZ_INS_ALFI, "alfi" },
	{ SYSZ_INS_ALG, "alg" },
	{ SYSZ_INS_ALGF, "algf" },
	{ SYSZ_INS_ALGFI, "algfi" },
	{ SYSZ_INS_ALGFR, "algfr" },
	{ SYSZ_INS_ALGHSIK, "alghsik" },
	{ SYSZ_INS_ALGR, "algr" },
	{ SYSZ_INS_ALGRK, "algrk" },
	{ SYSZ_INS_ALHSIK, "alhsik" },
	{ SYSZ_INS_ALR, "alr" },
	{ SYSZ_INS_ALRK, "alrk" },
	{ SYSZ_INS_ALY, "aly" },
	{ SYSZ_INS_AR, "ar" },
	{ SYSZ_INS_ARK, "ark" },
	{ SYSZ_INS_ASI, "asi" },
	{ SYSZ_INS_AXBR, "axbr" },
	{ SYSZ_INS_AY, "ay" },
	{ SYSZ_INS_BCR, "bcr" },
	{ SYSZ_INS_BRC, "brc" },
	{ SYSZ_INS_BRCL, "brcl" },
	{ SYSZ_INS_CGIJ, "cgij" },
	{ SYSZ_INS_CGRJ, "cgrj" },
	{ SYSZ_INS_CIJ, "cij" },
	{ SYSZ_INS_CLGIJ, "clgij" },
	{ SYSZ_INS_CLGRJ, "clgrj" },
	{ SYSZ_INS_CLIJ, "clij" },
	{ SYSZ_INS_CLRJ, "clrj" },
	{ SYSZ_INS_CRJ, "crj" },
	{ SYSZ_INS_BER, "ber" },
	{ SYSZ_INS_JE, "je" },
	{ SYSZ_INS_JGE, "jge" },
	{ SYSZ_INS_LOCE, "loce" },
	{ SYSZ_INS_LOCGE, "locge" },
	{ SYSZ_INS_LOCGRE, "locgre" },
	{ SYSZ_INS_LOCRE, "locre" },
	{ SYSZ_INS_STOCE, "stoce" },
	{ SYSZ_INS_STOCGE, "stocge" },
	{ SYSZ_INS_BHR, "bhr" },
	{ SYSZ_INS_BHER, "bher" },
	{ SYSZ_INS_JHE, "jhe" },
	{ SYSZ_INS_JGHE, "jghe" },
	{ SYSZ_INS_LOCHE, "loche" },
	{ SYSZ_INS_LOCGHE, "locghe" },
	{ SYSZ_INS_LOCGRHE, "locgrhe" },
	{ SYSZ_INS_LOCRHE, "locrhe" },
	{ SYSZ_INS_STOCHE, "stoche" },
	{ SYSZ_INS_STOCGHE, "stocghe" },
	{ SYSZ_INS_JH, "jh" },
	{ SYSZ_INS_JGH, "jgh" },
	{ SYSZ_INS_LOCH, "loch" },
	{ SYSZ_INS_LOCGH, "locgh" },
	{ SYSZ_INS_LOCGRH, "locgrh" },
	{ SYSZ_INS_LOCRH, "locrh" },
	{ SYSZ_INS_STOCH, "stoch" },
	{ SYSZ_INS_STOCGH, "stocgh" },
	{ SYSZ_INS_CGIJNLH, "cgijnlh" },
	{ SYSZ_INS_CGRJNLH, "cgrjnlh" },
	{ SYSZ_INS_CIJNLH, "cijnlh" },
	{ SYSZ_INS_CLGIJNLH, "clgijnlh" },
	{ SYSZ_INS_CLGRJNLH, "clgrjnlh" },
	{ SYSZ_INS_CLIJNLH, "clijnlh" },
	{ SYSZ_INS_CLRJNLH, "clrjnlh" },
	{ SYSZ_INS_CRJNLH, "crjnlh" },
	{ SYSZ_INS_CGIJE, "cgije" },
	{ SYSZ_INS_CGRJE, "cgrje" },
	{ SYSZ_INS_CIJE, "cije" },
	{ SYSZ_INS_CLGIJE, "clgije" },
	{ SYSZ_INS_CLGRJE, "clgrje" },
	{ SYSZ_INS_CLIJE, "clije" },
	{ SYSZ_INS_CLRJE, "clrje" },
	{ SYSZ_INS_CRJE, "crje" },
	{ SYSZ_INS_CGIJNLE, "cgijnle" },
	{ SYSZ_INS_CGRJNLE, "cgrjnle" },
	{ SYSZ_INS_CIJNLE, "cijnle" },
	{ SYSZ_INS_CLGIJNLE, "clgijnle" },
	{ SYSZ_INS_CLGRJNLE, "clgrjnle" },
	{ SYSZ_INS_CLIJNLE, "clijnle" },
	{ SYSZ_INS_CLRJNLE, "clrjnle" },
	{ SYSZ_INS_CRJNLE, "crjnle" },
	{ SYSZ_INS_CGIJH, "cgijh" },
	{ SYSZ_INS_CGRJH, "cgrjh" },
	{ SYSZ_INS_CIJH, "cijh" },
	{ SYSZ_INS_CLGIJH, "clgijh" },
	{ SYSZ_INS_CLGRJH, "clgrjh" },
	{ SYSZ_INS_CLIJH, "clijh" },
	{ SYSZ_INS_CLRJH, "clrjh" },
	{ SYSZ_INS_CRJH, "crjh" },
	{ SYSZ_INS_CGIJNL, "cgijnl" },
	{ SYSZ_INS_CGRJNL, "cgrjnl" },
	{ SYSZ_INS_CIJNL, "cijnl" },
	{ SYSZ_INS_CLGIJNL, "clgijnl" },
	{ SYSZ_INS_CLGRJNL, "clgrjnl" },
	{ SYSZ_INS_CLIJNL, "clijnl" },
	{ SYSZ_INS_CLRJNL, "clrjnl" },
	{ SYSZ_INS_CRJNL, "crjnl" },
	{ SYSZ_INS_CGIJHE, "cgijhe" },
	{ SYSZ_INS_CGRJHE, "cgrjhe" },
	{ SYSZ_INS_CIJHE, "cijhe" },
	{ SYSZ_INS_CLGIJHE, "clgijhe" },
	{ SYSZ_INS_CLGRJHE, "clgrjhe" },
	{ SYSZ_INS_CLIJHE, "clijhe" },
	{ SYSZ_INS_CLRJHE, "clrjhe" },
	{ SYSZ_INS_CRJHE, "crjhe" },
	{ SYSZ_INS_CGIJNHE, "cgijnhe" },
	{ SYSZ_INS_CGRJNHE, "cgrjnhe" },
	{ SYSZ_INS_CIJNHE, "cijnhe" },
	{ SYSZ_INS_CLGIJNHE, "clgijnhe" },
	{ SYSZ_INS_CLGRJNHE, "clgrjnhe" },
	{ SYSZ_INS_CLIJNHE, "clijnhe" },
	{ SYSZ_INS_CLRJNHE, "clrjnhe" },
	{ SYSZ_INS_CRJNHE, "crjnhe" },
	{ SYSZ_INS_CGIJL, "cgijl" },
	{ SYSZ_INS_CGRJL, "cgrjl" },
	{ SYSZ_INS_CIJL, "cijl" },
	{ SYSZ_INS_CLGIJL, "clgijl" },
	{ SYSZ_INS_CLGRJL, "clgrjl" },
	{ SYSZ_INS_CLIJL, "clijl" },
	{ SYSZ_INS_CLRJL, "clrjl" },
	{ SYSZ_INS_CRJL, "crjl" },
	{ SYSZ_INS_CGIJNH, "cgijnh" },
	{ SYSZ_INS_CGRJNH, "cgrjnh" },
	{ SYSZ_INS_CIJNH, "cijnh" },
	{ SYSZ_INS_CLGIJNH, "clgijnh" },
	{ SYSZ_INS_CLGRJNH, "clgrjnh" },
	{ SYSZ_INS_CLIJNH, "clijnh" },
	{ SYSZ_INS_CLRJNH, "clrjnh" },
	{ SYSZ_INS_CRJNH, "crjnh" },
	{ SYSZ_INS_CGIJLE, "cgijle" },
	{ SYSZ_INS_CGRJLE, "cgrjle" },
	{ SYSZ_INS_CIJLE, "cijle" },
	{ SYSZ_INS_CLGIJLE, "clgijle" },
	{ SYSZ_INS_CLGRJLE, "clgrjle" },
	{ SYSZ_INS_CLIJLE, "clijle" },
	{ SYSZ_INS_CLRJLE, "clrjle" },
	{ SYSZ_INS_CRJLE, "crjle" },
	{ SYSZ_INS_CGIJNE, "cgijne" },
	{ SYSZ_INS_CGRJNE, "cgrjne" },
	{ SYSZ_INS_CIJNE, "cijne" },
	{ SYSZ_INS_CLGIJNE, "clgijne" },
	{ SYSZ_INS_CLGRJNE, "clgrjne" },
	{ SYSZ_INS_CLIJNE, "clijne" },
	{ SYSZ_INS_CLRJNE, "clrjne" },
	{ SYSZ_INS_CRJNE, "crjne" },
	{ SYSZ_INS_CGIJLH, "cgijlh" },
	{ SYSZ_INS_CGRJLH, "cgrjlh" },
	{ SYSZ_INS_CIJLH, "cijlh" },
	{ SYSZ_INS_CLGIJLH, "clgijlh" },
	{ SYSZ_INS_CLGRJLH, "clgrjlh" },
	{ SYSZ_INS_CLIJLH, "clijlh" },
	{ SYSZ_INS_CLRJLH, "clrjlh" },
	{ SYSZ_INS_CRJLH, "crjlh" },
	{ SYSZ_INS_BLR, "blr" },
	{ SYSZ_INS_BLER, "bler" },
	{ SYSZ_INS_JLE, "jle" },
	{ SYSZ_INS_JGLE, "jgle" },
	{ SYSZ_INS_LOCLE, "locle" },
	{ SYSZ_INS_LOCGLE, "locgle" },
	{ SYSZ_INS_LOCGRLE, "locgrle" },
	{ SYSZ_INS_LOCRLE, "locrle" },
	{ SYSZ_INS_STOCLE, "stocle" },
	{ SYSZ_INS_STOCGLE, "stocgle" },
	{ SYSZ_INS_BLHR, "blhr" },
	{ SYSZ_INS_JLH, "jlh" },
	{ SYSZ_INS_JGLH, "jglh" },
	{ SYSZ_INS_LOCLH, "loclh" },
	{ SYSZ_INS_LOCGLH, "locglh" },
	{ SYSZ_INS_LOCGRLH, "locgrlh" },
	{ SYSZ_INS_LOCRLH, "locrlh" },
	{ SYSZ_INS_STOCLH, "stoclh" },
	{ SYSZ_INS_STOCGLH, "stocglh" },
	{ SYSZ_INS_JL, "jl" },
	{ SYSZ_INS_JGL, "jgl" },
	{ SYSZ_INS_LOCL, "locl" },
	{ SYSZ_INS_LOCGL, "locgl" },
	{ SYSZ_INS_LOCGRL, "locgrl" },
	{ SYSZ_INS_LOCRL, "locrl" },
	{ SYSZ_INS_LOC, "loc" },
	{ SYSZ_INS_LOCG, "locg" },
	{ SYSZ_INS_LOCGR, "locgr" },
	{ SYSZ_INS_LOCR, "locr" },
	{ SYSZ_INS_STOCL, "stocl" },
	{ SYSZ_INS_STOCGL, "stocgl" },
	{ SYSZ_INS_BNER, "bner" },
	{ SYSZ_INS_JNE, "jne" },
	{ SYSZ_INS_JGNE, "jgne" },
	{ SYSZ_INS_LOCNE, "locne" },
	{ SYSZ_INS_LOCGNE, "locgne" },
	{ SYSZ_INS_LOCGRNE, "locgrne" },
	{ SYSZ_INS_LOCRNE, "locrne" },
	{ SYSZ_INS_STOCNE, "stocne" },
	{ SYSZ_INS_STOCGNE, "stocgne" },
	{ SYSZ_INS_BNHR, "bnhr" },
	{ SYSZ_INS_BNHER, "bnher" },
	{ SYSZ_INS_JNHE, "jnhe" },
	{ SYSZ_INS_JGNHE, "jgnhe" },
	{ SYSZ_INS_LOCNHE, "locnhe" },
	{ SYSZ_INS_LOCGNHE, "locgnhe" },
	{ SYSZ_INS_LOCGRNHE, "locgrnhe" },
	{ SYSZ_INS_LOCRNHE, "locrnhe" },
	{ SYSZ_INS_STOCNHE, "stocnhe" },
	{ SYSZ_INS_STOCGNHE, "stocgnhe" },
	{ SYSZ_INS_JNH, "jnh" },
	{ SYSZ_INS_JGNH, "jgnh" },
	{ SYSZ_INS_LOCNH, "locnh" },
	{ SYSZ_INS_LOCGNH, "locgnh" },
	{ SYSZ_INS_LOCGRNH, "locgrnh" },
	{ SYSZ_INS_LOCRNH, "locrnh" },
	{ SYSZ_INS_STOCNH, "stocnh" },
	{ SYSZ_INS_STOCGNH, "stocgnh" },
	{ SYSZ_INS_BNLR, "bnlr" },
	{ SYSZ_INS_BNLER, "bnler" },
	{ SYSZ_INS_JNLE, "jnle" },
	{ SYSZ_INS_JGNLE, "jgnle" },
	{ SYSZ_INS_LOCNLE, "locnle" },
	{ SYSZ_INS_LOCGNLE, "locgnle" },
	{ SYSZ_INS_LOCGRNLE, "locgrnle" },
	{ SYSZ_INS_LOCRNLE, "locrnle" },
	{ SYSZ_INS_STOCNLE, "stocnle" },
	{ SYSZ_INS_STOCGNLE, "stocgnle" },
	{ SYSZ_INS_BNLHR, "bnlhr" },
	{ SYSZ_INS_JNLH, "jnlh" },
	{ SYSZ_INS_JGNLH, "jgnlh" },
	{ SYSZ_INS_LOCNLH, "locnlh" },
	{ SYSZ_INS_LOCGNLH, "locgnlh" },
	{ SYSZ_INS_LOCGRNLH, "locgrnlh" },
	{ SYSZ_INS_LOCRNLH, "locrnlh" },
	{ SYSZ_INS_STOCNLH, "stocnlh" },
	{ SYSZ_INS_STOCGNLH, "stocgnlh" },
	{ SYSZ_INS_JNL, "jnl" },
	{ SYSZ_INS_JGNL, "jgnl" },
	{ SYSZ_INS_LOCNL, "locnl" },
	{ SYSZ_INS_LOCGNL, "locgnl" },
	{ SYSZ_INS_LOCGRNL, "locgrnl" },
	{ SYSZ_INS_LOCRNL, "locrnl" },
	{ SYSZ_INS_STOCNL, "stocnl" },
	{ SYSZ_INS_STOCGNL, "stocgnl" },
	{ SYSZ_INS_BNOR, "bnor" },
	{ SYSZ_INS_JNO, "jno" },
	{ SYSZ_INS_JGNO, "jgno" },
	{ SYSZ_INS_LOCNO, "locno" },
	{ SYSZ_INS_LOCGNO, "locgno" },
	{ SYSZ_INS_LOCGRNO, "locgrno" },
	{ SYSZ_INS_LOCRNO, "locrno" },
	{ SYSZ_INS_STOCNO, "stocno" },
	{ SYSZ_INS_STOCGNO, "stocgno" },
	{ SYSZ_INS_BOR, "bor" },
	{ SYSZ_INS_JO, "jo" },
	{ SYSZ_INS_JGO, "jgo" },
	{ SYSZ_INS_LOCO, "loco" },
	{ SYSZ_INS_LOCGO, "locgo" },
	{ SYSZ_INS_LOCGRO, "locgro" },
	{ SYSZ_INS_LOCRO, "locro" },
	{ SYSZ_INS_STOCO, "stoco" },
	{ SYSZ_INS_STOCGO, "stocgo" },
	{ SYSZ_INS_STOC, "stoc" },
	{ SYSZ_INS_STOCG, "stocg" },
	{ SYSZ_INS_BASR, "basr" },
	{ SYSZ_INS_BR, "br" },
	{ SYSZ_INS_BRAS, "bras" },
	{ SYSZ_INS_BRASL, "brasl" },
	{ SYSZ_INS_J, "j" },
	{ SYSZ_INS_JG, "jg" },
	{ SYSZ_INS_BRCT, "brct" },
	{ SYSZ_INS_BRCTG, "brctg" },
	{ SYSZ_INS_C, "c" },
	{ SYSZ_INS_CDB, "cdb" },
	{ SYSZ_INS_CDBR, "cdbr" },
	{ SYSZ_INS_CDFBR, "cdfbr" },
	{ SYSZ_INS_CDGBR, "cdgbr" },
	{ SYSZ_INS_CDLFBR, "cdlfbr" },
	{ SYSZ_INS_CDLGBR, "cdlgbr" },
	{ SYSZ_INS_CEB, "ceb" },
	{ SYSZ_INS_CEBR, "cebr" },
	{ SYSZ_INS_CEFBR, "cefbr" },
	{ SYSZ_INS_CEGBR, "cegbr" },
	{ SYSZ_INS_CELFBR, "celfbr" },
	{ SYSZ_INS_CELGBR, "celgbr" },
	{ SYSZ_INS_CFDBR, "cfdbr" },
	{ SYSZ_INS_CFEBR, "cfebr" },
	{ SYSZ_INS_CFI, "cfi" },
	{ SYSZ_INS_CFXBR, "cfxbr" },
	{ SYSZ_INS_CG, "cg" },
	{ SYSZ_INS_CGDBR, "cgdbr" },
	{ SYSZ_INS_CGEBR, "cgebr" },
	{ SYSZ_INS_CGF, "cgf" },
	{ SYSZ_INS_CGFI, "cgfi" },
	{ SYSZ_INS_CGFR, "cgfr" },
	{ SYSZ_INS_CGFRL, "cgfrl" },
	{ SYSZ_INS_CGH, "cgh" },
	{ SYSZ_INS_CGHI, "cghi" },
	{ SYSZ_INS_CGHRL, "cghrl" },
	{ SYSZ_INS_CGHSI, "cghsi" },
	{ SYSZ_INS_CGR, "cgr" },
	{ SYSZ_INS_CGRL, "cgrl" },
	{ SYSZ_INS_CGXBR, "cgxbr" },
	{ SYSZ_INS_CH, "ch" },
	{ SYSZ_INS_CHF, "chf" },
	{ SYSZ_INS_CHHSI, "chhsi" },
	{ SYSZ_INS_CHI, "chi" },
	{ SYSZ_INS_CHRL, "chrl" },
	{ SYSZ_INS_CHSI, "chsi" },
	{ SYSZ_INS_CHY, "chy" },
	{ SYSZ_INS_CIH, "cih" },
	{ SYSZ_INS_CL, "cl" },
	{ SYSZ_INS_CLC, "clc" },
	{ SYSZ_INS_CLFDBR, "clfdbr" },
	{ SYSZ_INS_CLFEBR, "clfebr" },
	{ SYSZ_INS_CLFHSI, "clfhsi" },
	{ SYSZ_INS_CLFI, "clfi" },
	{ SYSZ_INS_CLFXBR, "clfxbr" },
	{ SYSZ_INS_CLG, "clg" },
	{ SYSZ_INS_CLGDBR, "clgdbr" },
	{ SYSZ_INS_CLGEBR, "clgebr" },
	{ SYSZ_INS_CLGF, "clgf" },
	{ SYSZ_INS_CLGFI, "clgfi" },
	{ SYSZ_INS_CLGFR, "clgfr" },
	{ SYSZ_INS_CLGFRL, "clgfrl" },
	{ SYSZ_INS_CLGHRL, "clghrl" },
	{ SYSZ_INS_CLGHSI, "clghsi" },
	{ SYSZ_INS_CLGR, "clgr" },
	{ SYSZ_INS_CLGRL, "clgrl" },
	{ SYSZ_INS_CLGXBR, "clgxbr" },
	{ SYSZ_INS_CLHF, "clhf" },
	{ SYSZ_INS_CLHHSI, "clhhsi" },
	{ SYSZ_INS_CLHRL, "clhrl" },
	{ SYSZ_INS_CLI, "cli" },
	{ SYSZ_INS_CLIH, "clih" },
	{ SYSZ_INS_CLIY, "cliy" },
	{ SYSZ_INS_CLR, "clr" },
	{ SYSZ_INS_CLRL, "clrl" },
	{ SYSZ_INS_CLST, "clst" },
	{ SYSZ_INS_CLY, "cly" },
	{ SYSZ_INS_CPSDR, "cpsdr" },
	{ SYSZ_INS_CR, "cr" },
	{ SYSZ_INS_CRL, "crl" },
	{ SYSZ_INS_CS, "cs" },
	{ SYSZ_INS_CSG, "csg" },
	{ SYSZ_INS_CSY, "csy" },
	{ SYSZ_INS_CXBR, "cxbr" },
	{ SYSZ_INS_CXFBR, "cxfbr" },
	{ SYSZ_INS_CXGBR, "cxgbr" },
	{ SYSZ_INS_CXLFBR, "cxlfbr" },
	{ SYSZ_INS_CXLGBR, "cxlgbr" },
	{ SYSZ_INS_CY, "cy" },
	{ SYSZ_INS_DDB, "ddb" },
	{ SYSZ_INS_DDBR, "ddbr" },
	{ SYSZ_INS_DEB, "deb" },
	{ SYSZ_INS_DEBR, "debr" },
	{ SYSZ_INS_DL, "dl" },
	{ SYSZ_INS_DLG, "dlg" },
	{ SYSZ_INS_DLGR, "dlgr" },
	{ SYSZ_INS_DLR, "dlr" },
	{ SYSZ_INS_DSG, "dsg" },
	{ SYSZ_INS_DSGF, "dsgf" },
	{ SYSZ_INS_DSGFR, "dsgfr" },
	{ SYSZ_INS_DSGR, "dsgr" },
	{ SYSZ_INS_DXBR, "dxbr" },
	{ SYSZ_INS_EAR, "ear" },
	{ SYSZ_INS_FIDBR, "fidbr" },
	{ SYSZ_INS_FIDBRA, "fidbra" },
	{ SYSZ_INS_FIEBR, "fiebr" },
	{ SYSZ_INS_FIEBRA, "fiebra" },
	{ SYSZ_INS_FIXBR, "fixbr" },
	{ SYSZ_INS_FIXBRA, "fixbra" },
	{ SYSZ_INS_FLOGR, "flogr" },
	{ SYSZ_INS_IC, "ic" },
	{ SYSZ_INS_ICY, "icy" },
	{ SYSZ_INS_IIHF, "iihf" },
	{ SYSZ_INS_IIHH, "iihh" },
	{ SYSZ_INS_IIHL, "iihl" },
	{ SYSZ_INS_IILF, "iilf" },
	{ SYSZ_INS_IILH, "iilh" },
	{ SYSZ_INS_IILL, "iill" },
	{ SYSZ_INS_IPM, "ipm" },
	{ SYSZ_INS_L, "l" },
	{ SYSZ_INS_LA, "la" },
	{ SYSZ_INS_LAA, "laa" },
	{ SYSZ_INS_LAAG, "laag" },
	{ SYSZ_INS_LAAL, "laal" },
	{ SYSZ_INS_LAALG, "laalg" },
	{ SYSZ_INS_LAN, "lan" },
	{ SYSZ_INS_LANG, "lang" },
	{ SYSZ_INS_LAO, "lao" },
	{ SYSZ_INS_LAOG, "laog" },
	{ SYSZ_INS_LARL, "larl" },
	{ SYSZ_INS_LAX, "lax" },
	{ SYSZ_INS_LAXG, "laxg" },
	{ SYSZ_INS_LAY, "lay" },
	{ SYSZ_INS_LB, "lb" },
	{ SYSZ_INS_LBH, "lbh" },
	{ SYSZ_INS_LBR, "lbr" },
	{ SYSZ_INS_LCDBR, "lcdbr" },
	{ SYSZ_INS_LCEBR, "lcebr" },
	{ SYSZ_INS_LCGFR, "lcgfr" },
	{ SYSZ_INS_LCGR, "lcgr" },
	{ SYSZ_INS_LCR, "lcr" },
	{ SYSZ_INS_LCXBR, "lcxbr" },
	{ SYSZ_INS_LD, "ld" },
	{ SYSZ_INS_LDEB, "ldeb" },
	{ SYSZ_INS_LDEBR, "ldebr" },
	{ SYSZ_INS_LDGR, "ldgr" },
	{ SYSZ_INS_LDR, "ldr" },
	{ SYSZ_INS_LDXBR, "ldxbr" },
	{ SYSZ_INS_LDXBRA, "ldxbra" },
	{ SYSZ_INS_LDY, "ldy" },
	{ SYSZ_INS_LE, "le" },
	{ SYSZ_INS_LEDBR, "ledbr" },
	{ SYSZ_INS_LEDBRA, "ledbra" },
	{ SYSZ_INS_LER, "ler" },
	{ SYSZ_INS_LEXBR, "lexbr" },
	{ SYSZ_INS_LEXBRA, "lexbra" },
	{ SYSZ_INS_LEY, "ley" },
	{ SYSZ_INS_LFH, "lfh" },
	{ SYSZ_INS_LG, "lg" },
	{ SYSZ_INS_LGB, "lgb" },
	{ SYSZ_INS_LGBR, "lgbr" },
	{ SYSZ_INS_LGDR, "lgdr" },
	{ SYSZ_INS_LGF, "lgf" },
	{ SYSZ_INS_LGFI, "lgfi" },
	{ SYSZ_INS_LGFR, "lgfr" },
	{ SYSZ_INS_LGFRL, "lgfrl" },
	{ SYSZ_INS_LGH, "lgh" },
	{ SYSZ_INS_LGHI, "lghi" },
	{ SYSZ_INS_LGHR, "lghr" },
	{ SYSZ_INS_LGHRL, "lghrl" },
	{ SYSZ_INS_LGR, "lgr" },
	{ SYSZ_INS_LGRL, "lgrl" },
	{ SYSZ_INS_LH, "lh" },
	{ SYSZ_INS_LHH, "lhh" },
	{ SYSZ_INS_LHI, "lhi" },
	{ SYSZ_INS_LHR, "lhr" },
	{ SYSZ_INS_LHRL, "lhrl" },
	{ SYSZ_INS_LHY, "lhy" },
	{ SYSZ_INS_LLC, "llc" },
	{ SYSZ_INS_LLCH, "llch" },
	{ SYSZ_INS_LLCR, "llcr" },
	{ SYSZ_INS_LLGC, "llgc" },
	{ SYSZ_INS_LLGCR, "llgcr" },
	{ SYSZ_INS_LLGF, "llgf" },
	{ SYSZ_INS_LLGFR, "llgfr" },
	{ SYSZ_INS_LLGFRL, "llgfrl" },
	{ SYSZ_INS_LLGH, "llgh" },
	{ SYSZ_INS_LLGHR, "llghr" },
	{ SYSZ_INS_LLGHRL, "llghrl" },
	{ SYSZ_INS_LLH, "llh" },
	{ SYSZ_INS_LLHH, "llhh" },
	{ SYSZ_INS_LLHR, "llhr" },
	{ SYSZ_INS_LLHRL, "llhrl" },
	{ SYSZ_INS_LLIHF, "llihf" },
	{ SYSZ_INS_LLIHH, "llihh" },
	{ SYSZ_INS_LLIHL, "llihl" },
	{ SYSZ_INS_LLILF, "llilf" },
	{ SYSZ_INS_LLILH, "llilh" },
	{ SYSZ_INS_LLILL, "llill" },
	{ SYSZ_INS_LMG, "lmg" },
	{ SYSZ_INS_LNDBR, "lndbr" },
	{ SYSZ_INS_LNEBR, "lnebr" },
	{ SYSZ_INS_LNGFR, "lngfr" },
	{ SYSZ_INS_LNGR, "lngr" },
	{ SYSZ_INS_LNR, "lnr" },
	{ SYSZ_INS_LNXBR, "lnxbr" },
	{ SYSZ_INS_LPDBR, "lpdbr" },
	{ SYSZ_INS_LPEBR, "lpebr" },
	{ SYSZ_INS_LPGFR, "lpgfr" },
	{ SYSZ_INS_LPGR, "lpgr" },
	{ SYSZ_INS_LPR, "lpr" },
	{ SYSZ_INS_LPXBR, "lpxbr" },
	{ SYSZ_INS_LR, "lr" },
	{ SYSZ_INS_LRL, "lrl" },
	{ SYSZ_INS_LRV, "lrv" },
	{ SYSZ_INS_LRVG, "lrvg" },
	{ SYSZ_INS_LRVGR, "lrvgr" },
	{ SYSZ_INS_LRVR, "lrvr" },
	{ SYSZ_INS_LT, "lt" },
	{ SYSZ_INS_LTDBR, "ltdbr" },
	{ SYSZ_INS_LTEBR, "ltebr" },
	{ SYSZ_INS_LTG, "ltg" },
	{ SYSZ_INS_LTGF, "ltgf" },
	{ SYSZ_INS_LTGFR, "ltgfr" },
	{ SYSZ_INS_LTGR, "ltgr" },
	{ SYSZ_INS_LTR, "ltr" },
	{ SYSZ_INS_LTXBR, "ltxbr" },
	{ SYSZ_INS_LXDB, "lxdb" },
	{ SYSZ_INS_LXDBR, "lxdbr" },
	{ SYSZ_INS_LXEB, "lxeb" },
	{ SYSZ_INS_LXEBR, "lxebr" },
	{ SYSZ_INS_LXR, "lxr" },
	{ SYSZ_INS_LY, "ly" },
	{ SYSZ_INS_LZDR, "lzdr" },
	{ SYSZ_INS_LZER, "lzer" },
	{ SYSZ_INS_LZXR, "lzxr" },
	{ SYSZ_INS_MADB, "madb" },
	{ SYSZ_INS_MADBR, "madbr" },
	{ SYSZ_INS_MAEB, "maeb" },
	{ SYSZ_INS_MAEBR, "maebr" },
	{ SYSZ_INS_MDB, "mdb" },
	{ SYSZ_INS_MDBR, "mdbr" },
	{ SYSZ_INS_MDEB, "mdeb" },
	{ SYSZ_INS_MDEBR, "mdebr" },
	{ SYSZ_INS_MEEB, "meeb" },
	{ SYSZ_INS_MEEBR, "meebr" },
	{ SYSZ_INS_MGHI, "mghi" },
	{ SYSZ_INS_MH, "mh" },
	{ SYSZ_INS_MHI, "mhi" },
	{ SYSZ_INS_MHY, "mhy" },
	{ SYSZ_INS_MLG, "mlg" },
	{ SYSZ_INS_MLGR, "mlgr" },
	{ SYSZ_INS_MS, "ms" },
	{ SYSZ_INS_MSDB, "msdb" },
	{ SYSZ_INS_MSDBR, "msdbr" },
	{ SYSZ_INS_MSEB, "mseb" },
	{ SYSZ_INS_MSEBR, "msebr" },
	{ SYSZ_INS_MSFI, "msfi" },
	{ SYSZ_INS_MSG, "msg" },
	{ SYSZ_INS_MSGF, "msgf" },
	{ SYSZ_INS_MSGFI, "msgfi" },
	{ SYSZ_INS_MSGFR, "msgfr" },
	{ SYSZ_INS_MSGR, "msgr" },
	{ SYSZ_INS_MSR, "msr" },
	{ SYSZ_INS_MSY, "msy" },
	{ SYSZ_INS_MVC, "mvc" },
	{ SYSZ_INS_MVGHI, "mvghi" },
	{ SYSZ_INS_MVHHI, "mvhhi" },
	{ SYSZ_INS_MVHI, "mvhi" },
	{ SYSZ_INS_MVI, "mvi" },
	{ SYSZ_INS_MVIY, "mviy" },
	{ SYSZ_INS_MVST, "mvst" },
	{ SYSZ_INS_MXBR, "mxbr" },
	{ SYSZ_INS_MXDB, "mxdb" },
	{ SYSZ_INS_MXDBR, "mxdbr" },
	{ SYSZ_INS_N, "n" },
	{ SYSZ_INS_NC, "nc" },
	{ SYSZ_INS_NG, "ng" },
	{ SYSZ_INS_NGR, "ngr" },
	{ SYSZ_INS_NGRK, "ngrk" },
	{ SYSZ_INS_NI, "ni" },
	{ SYSZ_INS_NIHF, "nihf" },
	{ SYSZ_INS_NIHH, "nihh" },
	{ SYSZ_INS_NIHL, "nihl" },
	{ SYSZ_INS_NILF, "nilf" },
	{ SYSZ_INS_NILH, "nilh" },
	{ SYSZ_INS_NILL, "nill" },
	{ SYSZ_INS_NIY, "niy" },
	{ SYSZ_INS_NR, "nr" },
	{ SYSZ_INS_NRK, "nrk" },
	{ SYSZ_INS_NY, "ny" },
	{ SYSZ_INS_O, "o" },
	{ SYSZ_INS_OC, "oc" },
	{ SYSZ_INS_OG, "og" },
	{ SYSZ_INS_OGR, "ogr" },
	{ SYSZ_INS_OGRK, "ogrk" },
	{ SYSZ_INS_OI, "oi" },
	{ SYSZ_INS_OIHF, "oihf" },
	{ SYSZ_INS_OIHH, "oihh" },
	{ SYSZ_INS_OIHL, "oihl" },
	{ SYSZ_INS_OILF, "oilf" },
	{ SYSZ_INS_OILH, "oilh" },
	{ SYSZ_INS_OILL, "oill" },
	{ SYSZ_INS_OIY, "oiy" },
	{ SYSZ_INS_OR, "or" },
	{ SYSZ_INS_ORK, "ork" },
	{ SYSZ_INS_OY, "oy" },
	{ SYSZ_INS_PFD, "pfd" },
	{ SYSZ_INS_PFDRL, "pfdrl" },
	{ SYSZ_INS_RISBG, "risbg" },
	{ SYSZ_INS_RISBHG, "risbhg" },
	{ SYSZ_INS_RISBLG, "risblg" },
	{ SYSZ_INS_RLL, "rll" },
	{ SYSZ_INS_RLLG, "rllg" },
	{ SYSZ_INS_RNSBG, "rnsbg" },
	{ SYSZ_INS_ROSBG, "rosbg" },
	{ SYSZ_INS_RXSBG, "rxsbg" },
	{ SYSZ_INS_S, "s" },
	{ SYSZ_INS_SDB, "sdb" },
	{ SYSZ_INS_SDBR, "sdbr" },
	{ SYSZ_INS_SEB, "seb" },
	{ SYSZ_INS_SEBR, "sebr" },
	{ SYSZ_INS_SG, "sg" },
	{ SYSZ_INS_SGF, "sgf" },
	{ SYSZ_INS_SGFR, "sgfr" },
	{ SYSZ_INS_SGR, "sgr" },
	{ SYSZ_INS_SGRK, "sgrk" },
	{ SYSZ_INS_SH, "sh" },
	{ SYSZ_INS_SHY, "shy" },
	{ SYSZ_INS_SL, "sl" },
	{ SYSZ_INS_SLB, "slb" },
	{ SYSZ_INS_SLBG, "slbg" },
	{ SYSZ_INS_SLBR, "slbr" },
	{ SYSZ_INS_SLFI, "slfi" },
	{ SYSZ_INS_SLG, "slg" },
	{ SYSZ_INS_SLBGR, "slbgr" },
	{ SYSZ_INS_SLGF, "slgf" },
	{ SYSZ_INS_SLGFI, "slgfi" },
	{ SYSZ_INS_SLGFR, "slgfr" },
	{ SYSZ_INS_SLGR, "slgr" },
	{ SYSZ_INS_SLGRK, "slgrk" },
	{ SYSZ_INS_SLL, "sll" },
	{ SYSZ_INS_SLLG, "sllg" },
	{ SYSZ_INS_SLLK, "sllk" },
	{ SYSZ_INS_SLR, "slr" },
	{ SYSZ_INS_SLRK, "slrk" },
	{ SYSZ_INS_SLY, "sly" },
	{ SYSZ_INS_SQDB, "sqdb" },
	{ SYSZ_INS_SQDBR, "sqdbr" },
	{ SYSZ_INS_SQEB, "sqeb" },
	{ SYSZ_INS_SQEBR, "sqebr" },
	{ SYSZ_INS_SQXBR, "sqxbr" },
	{ SYSZ_INS_SR, "sr" },
	{ SYSZ_INS_SRA, "sra" },
	{ SYSZ_INS_SRAG, "srag" },
	{ SYSZ_INS_SRAK, "srak" },
	{ SYSZ_INS_SRK, "srk" },
	{ SYSZ_INS_SRL, "srl" },
	{ SYSZ_INS_SRLG, "srlg" },
	{ SYSZ_INS_SRLK, "srlk" },
	{ SYSZ_INS_SRST, "srst" },
	{ SYSZ_INS_ST, "st" },
	{ SYSZ_INS_STC, "stc" },
	{ SYSZ_INS_STCH, "stch" },
	{ SYSZ_INS_STCY, "stcy" },
	{ SYSZ_INS_STD, "std" },
	{ SYSZ_INS_STDY, "stdy" },
	{ SYSZ_INS_STE, "ste" },
	{ SYSZ_INS_STEY, "stey" },
	{ SYSZ_INS_STFH, "stfh" },
	{ SYSZ_INS_STG, "stg" },
	{ SYSZ_INS_STGRL, "stgrl" },
	{ SYSZ_INS_STH, "sth" },
	{ SYSZ_INS_STHH, "sthh" },
	{ SYSZ_INS_STHRL, "sthrl" },
	{ SYSZ_INS_STHY, "sthy" },
	{ SYSZ_INS_STMG, "stmg" },
	{ SYSZ_INS_STRL, "strl" },
	{ SYSZ_INS_STRV, "strv" },
	{ SYSZ_INS_STRVG, "strvg" },
	{ SYSZ_INS_STY, "sty" },
	{ SYSZ_INS_SXBR, "sxbr" },
	{ SYSZ_INS_SY, "sy" },
	{ SYSZ_INS_TM, "tm" },
	{ SYSZ_INS_TMHH, "tmhh" },
	{ SYSZ_INS_TMHL, "tmhl" },
	{ SYSZ_INS_TMLH, "tmlh" },
	{ SYSZ_INS_TMLL, "tmll" },
	{ SYSZ_INS_TMY, "tmy" },
	{ SYSZ_INS_X, "x" },
	{ SYSZ_INS_XC, "xc" },
	{ SYSZ_INS_XG, "xg" },
	{ SYSZ_INS_XGR, "xgr" },
	{ SYSZ_INS_XGRK, "xgrk" },
	{ SYSZ_INS_XI, "xi" },
	{ SYSZ_INS_XIHF, "xihf" },
	{ SYSZ_INS_XILF, "xilf" },
	{ SYSZ_INS_XIY, "xiy" },
	{ SYSZ_INS_XR, "xr" },
	{ SYSZ_INS_XRK, "xrk" },
	{ SYSZ_INS_XY, "xy" },
};

// special alias insn
static const name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *SystemZ_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= SYSZ_INS_ENDING)
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
static const name_map group_name_maps[] = {
	// generic groups
	{ SYSZ_GRP_INVALID, NULL },
	{ SYSZ_GRP_JUMP, "jump" },

	// architecture-specific groups
	{ SYSZ_GRP_DISTINCTOPS, "distinctops" },
	{ SYSZ_GRP_FPEXTENSION, "fpextension" },
	{ SYSZ_GRP_HIGHWORD, "highword" },
	{ SYSZ_GRP_INTERLOCKEDACCESS1, "interlockedaccess1" },
	{ SYSZ_GRP_LOADSTOREONCOND, "loadstoreoncond" },
};
#endif

const char *SystemZ_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= SYSZ_GRP_ENDING || (id > SYSZ_GRP_JUMP && id < SYSZ_GRP_DISTINCTOPS))
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
sysz_reg SystemZ_map_register(unsigned int r)
{
	static const unsigned int map[] = { 0,
		SYSZ_REG_CC, SYSZ_REG_F0, SYSZ_REG_F1, SYSZ_REG_F2, SYSZ_REG_F3,
		SYSZ_REG_F4, SYSZ_REG_F5, SYSZ_REG_F6, SYSZ_REG_F7, SYSZ_REG_F8,
		SYSZ_REG_F9, SYSZ_REG_F10, SYSZ_REG_F11, SYSZ_REG_F12, SYSZ_REG_F13,
		SYSZ_REG_F14, SYSZ_REG_F15, SYSZ_REG_F0, SYSZ_REG_F1, SYSZ_REG_F4,
		SYSZ_REG_F5, SYSZ_REG_F8, SYSZ_REG_F9, SYSZ_REG_F12, SYSZ_REG_F13,
		SYSZ_REG_F0, SYSZ_REG_F1, SYSZ_REG_F2, SYSZ_REG_F3, SYSZ_REG_F4,
		SYSZ_REG_F5, SYSZ_REG_F6, SYSZ_REG_F7, SYSZ_REG_F8, SYSZ_REG_F9,
		SYSZ_REG_F10, SYSZ_REG_F11, SYSZ_REG_F12, SYSZ_REG_F13, SYSZ_REG_F14,
		SYSZ_REG_F15, SYSZ_REG_0, SYSZ_REG_1, SYSZ_REG_2, SYSZ_REG_3,
		SYSZ_REG_4, SYSZ_REG_5, SYSZ_REG_6, SYSZ_REG_7, SYSZ_REG_8,
		SYSZ_REG_9, SYSZ_REG_10, SYSZ_REG_11, SYSZ_REG_12, SYSZ_REG_13,
		SYSZ_REG_14, SYSZ_REG_15, SYSZ_REG_0, SYSZ_REG_1, SYSZ_REG_2,
		SYSZ_REG_3, SYSZ_REG_4, SYSZ_REG_5, SYSZ_REG_6, SYSZ_REG_7,
		SYSZ_REG_8, SYSZ_REG_9, SYSZ_REG_10, SYSZ_REG_11, SYSZ_REG_12,
		SYSZ_REG_13, SYSZ_REG_14, SYSZ_REG_15, SYSZ_REG_0, SYSZ_REG_1,
		SYSZ_REG_2, SYSZ_REG_3, SYSZ_REG_4, SYSZ_REG_5, SYSZ_REG_6,
		SYSZ_REG_7, SYSZ_REG_8, SYSZ_REG_9, SYSZ_REG_10, SYSZ_REG_11,
		SYSZ_REG_12, SYSZ_REG_13, SYSZ_REG_14, SYSZ_REG_15, SYSZ_REG_0,
		SYSZ_REG_2, SYSZ_REG_4, SYSZ_REG_6, SYSZ_REG_8, SYSZ_REG_10,
		SYSZ_REG_12, SYSZ_REG_14,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif
