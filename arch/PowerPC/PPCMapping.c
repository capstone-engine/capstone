/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "PPCMapping.h"

#define GET_INSTRINFO_ENUM
#include "PPCGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ PPC_REG_INVALID, NULL },

	{ PPC_REG_CARRY, "ca" },
	{ PPC_REG_CC, "cc"},
	{ PPC_REG_CR0, "cr0" },
	{ PPC_REG_CR1, "cr1" },
	{ PPC_REG_CR2, "cr2" },
	{ PPC_REG_CR3, "cr3" },
	{ PPC_REG_CR4, "cr4" },
	{ PPC_REG_CR5, "cr5" },
	{ PPC_REG_CR6, "cr6" },
	{ PPC_REG_CR7, "cr7" },
	{ PPC_REG_CTR, "ctr" },
	{ PPC_REG_F0, "f0" },
	{ PPC_REG_F1, "f1" },
	{ PPC_REG_F2, "f2" },
	{ PPC_REG_F3, "f3" },
	{ PPC_REG_F4, "f4" },
	{ PPC_REG_F5, "f5" },
	{ PPC_REG_F6, "f6" },
	{ PPC_REG_F7, "f7" },
	{ PPC_REG_F8, "f8" },
	{ PPC_REG_F9, "f9" },
	{ PPC_REG_F10, "f10" },
	{ PPC_REG_F11, "f11" },
	{ PPC_REG_F12, "f12" },
	{ PPC_REG_F13, "f13" },
	{ PPC_REG_F14, "f14" },
	{ PPC_REG_F15, "f15" },
	{ PPC_REG_F16, "f16" },
	{ PPC_REG_F17, "f17" },
	{ PPC_REG_F18, "f18" },
	{ PPC_REG_F19, "f19" },
	{ PPC_REG_F20, "f20" },
	{ PPC_REG_F21, "f21" },
	{ PPC_REG_F22, "f22" },
	{ PPC_REG_F23, "f23" },
	{ PPC_REG_F24, "f24" },
	{ PPC_REG_F25, "f25" },
	{ PPC_REG_F26, "f26" },
	{ PPC_REG_F27, "f27" },
	{ PPC_REG_F28, "f28" },
	{ PPC_REG_F29, "f29" },
	{ PPC_REG_F30, "f30" },
	{ PPC_REG_F31, "f31" },
	{ PPC_REG_LR, "lr" },
	{ PPC_REG_R0, "r0" },
	{ PPC_REG_R1, "r1" },
	{ PPC_REG_R2, "r2" },
	{ PPC_REG_R3, "r3" },
	{ PPC_REG_R4, "r4" },
	{ PPC_REG_R5, "r5" },
	{ PPC_REG_R6, "r6" },
	{ PPC_REG_R7, "r7" },
	{ PPC_REG_R8, "r8" },
	{ PPC_REG_R9, "r9" },
	{ PPC_REG_R10, "r10" },
	{ PPC_REG_R11, "r11" },
	{ PPC_REG_R12, "r12" },
	{ PPC_REG_R13, "r13" },
	{ PPC_REG_R14, "r14" },
	{ PPC_REG_R15, "r15" },
	{ PPC_REG_R16, "r16" },
	{ PPC_REG_R17, "r17" },
	{ PPC_REG_R18, "r18" },
	{ PPC_REG_R19, "r19" },
	{ PPC_REG_R20, "r20" },
	{ PPC_REG_R21, "r21" },
	{ PPC_REG_R22, "r22" },
	{ PPC_REG_R23, "r23" },
	{ PPC_REG_R24, "r24" },
	{ PPC_REG_R25, "r25" },
	{ PPC_REG_R26, "r26" },
	{ PPC_REG_R27, "r27" },
	{ PPC_REG_R28, "r28" },
	{ PPC_REG_R29, "r29" },
	{ PPC_REG_R30, "r30" },
	{ PPC_REG_R31, "r31" },
	{ PPC_REG_V0, "v0" },
	{ PPC_REG_V1, "v1" },
	{ PPC_REG_V2, "v2" },
	{ PPC_REG_V3, "v3" },
	{ PPC_REG_V4, "v4" },
	{ PPC_REG_V5, "v5" },
	{ PPC_REG_V6, "v6" },
	{ PPC_REG_V7, "v7" },
	{ PPC_REG_V8, "v8" },
	{ PPC_REG_V9, "v9" },
	{ PPC_REG_V10, "v10" },
	{ PPC_REG_V11, "v11" },
	{ PPC_REG_V12, "v12" },
	{ PPC_REG_V13, "v13" },
	{ PPC_REG_V14, "v14" },
	{ PPC_REG_V15, "v15" },
	{ PPC_REG_V16, "v16" },
	{ PPC_REG_V17, "v17" },
	{ PPC_REG_V18, "v18" },
	{ PPC_REG_V19, "v19" },
	{ PPC_REG_V20, "v20" },
	{ PPC_REG_V21, "v21" },
	{ PPC_REG_V22, "v22" },
	{ PPC_REG_V23, "v23" },
	{ PPC_REG_V24, "v24" },
	{ PPC_REG_V25, "v25" },
	{ PPC_REG_V26, "v26" },
	{ PPC_REG_V27, "v27" },
	{ PPC_REG_V28, "v28" },
	{ PPC_REG_V29, "v29" },
	{ PPC_REG_V30, "v30" },
	{ PPC_REG_V31, "v31" },
	{ PPC_REG_VRSAVE, "vrsave" },
	{ PPC_REG_VS0, "vs0"},
	{ PPC_REG_VS1, "vs1"},
	{ PPC_REG_VS2, "vs2"},
	{ PPC_REG_VS3, "vs3"},
	{ PPC_REG_VS4, "vs4"},
	{ PPC_REG_VS5, "vs5"},
	{ PPC_REG_VS6, "vs6"},
	{ PPC_REG_VS7, "vs7"},
	{ PPC_REG_VS8, "vs8"},
	{ PPC_REG_VS9, "vs9"},
	{ PPC_REG_VS10, "vs10"},
	{ PPC_REG_VS11, "vs11"},
	{ PPC_REG_VS12, "vs12"},
	{ PPC_REG_VS13, "vs13"},
	{ PPC_REG_VS14, "vs14"},
	{ PPC_REG_VS15, "vs15"},
	{ PPC_REG_VS16, "vs16"},
	{ PPC_REG_VS17, "vs17"},
	{ PPC_REG_VS18, "vs18"},
	{ PPC_REG_VS19, "vs19"},
	{ PPC_REG_VS20, "vs20"},
	{ PPC_REG_VS21, "vs21"},
	{ PPC_REG_VS22, "vs22"},
	{ PPC_REG_VS23, "vs23"},
	{ PPC_REG_VS24, "vs24"},
	{ PPC_REG_VS25, "vs25"},
	{ PPC_REG_VS26, "vs26"},
	{ PPC_REG_VS27, "vs27"},
	{ PPC_REG_VS28, "vs28"},
	{ PPC_REG_VS29, "vs29"},
	{ PPC_REG_VS30, "vs30"},
	{ PPC_REG_VS31, "vs31"},
	{ PPC_REG_VS32, "vs32"},
	{ PPC_REG_VS33, "vs33"},
	{ PPC_REG_VS34, "vs34"},
	{ PPC_REG_VS35, "vs35"},
	{ PPC_REG_VS36, "vs36"},
	{ PPC_REG_VS37, "vs37"},
	{ PPC_REG_VS38, "vs38"},
	{ PPC_REG_VS39, "vs39"},
	{ PPC_REG_VS40, "vs40"},
	{ PPC_REG_VS41, "vs41"},
	{ PPC_REG_VS42, "vs42"},
	{ PPC_REG_VS43, "vs43"},
	{ PPC_REG_VS44, "vs44"},
	{ PPC_REG_VS45, "vs45"},
	{ PPC_REG_VS46, "vs46"},
	{ PPC_REG_VS47, "vs47"},
	{ PPC_REG_VS48, "vs48"},
	{ PPC_REG_VS49, "vs49"},
	{ PPC_REG_VS50, "vs50"},
	{ PPC_REG_VS51, "vs51"},
	{ PPC_REG_VS52, "vs52"},
	{ PPC_REG_VS53, "vs53"},
	{ PPC_REG_VS54, "vs54"},
	{ PPC_REG_VS55, "vs55"},
	{ PPC_REG_VS56, "vs56"},
	{ PPC_REG_VS57, "vs57"},
	{ PPC_REG_VS58, "vs58"},
	{ PPC_REG_VS59, "vs59"},
	{ PPC_REG_VS60, "vs60"},
	{ PPC_REG_VS61, "vs61"},
	{ PPC_REG_VS62, "vs62"},
	{ PPC_REG_VS63, "vs63"},

	// extras
	{ PPC_REG_RM, "rm" },
	{ PPC_REG_CTR8, "ctr8" },
	{ PPC_REG_LR8, "lr8" },
	{ PPC_REG_CR1EQ, "cr1eq" },
};
#endif

const char *PPC_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= PPC_REG_ENDING)
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
		PPC_ADD4, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD4TLS, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD4o, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD8, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD8TLS, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD8TLS_, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADD8o, PPC_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDC, PPC_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDC8, PPC_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDC8o, PPC_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDCo, PPC_INS_ADDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDE, PPC_INS_ADDE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDE8, PPC_INS_ADDE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDE8o, PPC_INS_ADDE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDEo, PPC_INS_ADDE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDI, PPC_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDI8, PPC_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDIC, PPC_INS_ADDIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDIC8, PPC_INS_ADDIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDICo, PPC_INS_ADDIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDIS, PPC_INS_ADDIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDIS8, PPC_INS_ADDIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDME, PPC_INS_ADDME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDME8, PPC_INS_ADDME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDME8o, PPC_INS_ADDME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDMEo, PPC_INS_ADDME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDZE, PPC_INS_ADDZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDZE8, PPC_INS_ADDZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDZE8o, PPC_INS_ADDZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ADDZEo, PPC_INS_ADDZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_AND, PPC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_AND8, PPC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_AND8o, PPC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDC, PPC_INS_ANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDC8, PPC_INS_ANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDC8o, PPC_INS_ANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDCo, PPC_INS_ANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDISo, PPC_INS_ANDIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDISo8, PPC_INS_ANDIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDIo, PPC_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDIo8, PPC_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ANDo, PPC_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_B, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BA, PPC_INS_BA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BC, PPC_INS_BC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCC, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCCA, PPC_INS_BA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCCCTR, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		PPC_BCCCTR8, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_BCCCTRL, PPC_INS_BCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCCTRL8, PPC_INS_BCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { PPC_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		PPC_BCCL, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCLA, PPC_INS_BLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCLR, PPC_INS_BLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCCLRL, PPC_INS_BLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTR, PPC_INS_BCCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		PPC_BCCTR8, PPC_INS_BCCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_BCCTR8n, PPC_INS_BCCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_BCCTRL, PPC_INS_BCCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTRL8, PPC_INS_BCCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { PPC_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTRL8n, PPC_INS_BCCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { PPC_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTRLn, PPC_INS_BCCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTRn, PPC_INS_BCCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		PPC_BCL, PPC_INS_BCL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCLR, PPC_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCLRL, PPC_INS_BCLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCLRLn, PPC_INS_BCLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCLRn, PPC_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCLalways, PPC_INS_BCL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCLn, PPC_INS_BCL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCTR, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		PPC_BCTR8, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_BCTRL, PPC_INS_BCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { PPC_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		PPC_BCTRL8, PPC_INS_BCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { PPC_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		PPC_BCn, PPC_INS_BC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZ, PPC_INS_BDNZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZ8, PPC_INS_BDNZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZA, PPC_INS_BDNZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZAm, PPC_INS_BDNZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZAp, PPC_INS_BDNZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZL, PPC_INS_BDNZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLA, PPC_INS_BDNZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLAm, PPC_INS_BDNZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLAp, PPC_INS_BDNZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLR, PPC_INS_BDNZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZLR8, PPC_INS_BDNZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_LR8, PPC_REG_RM, 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZLRL, PPC_INS_BDNZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLRLm, PPC_INS_BDNZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLRLp, PPC_INS_BDNZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLRm, PPC_INS_BDNZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZLRp, PPC_INS_BDNZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZLm, PPC_INS_BDNZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZLp, PPC_INS_BDNZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDNZm, PPC_INS_BDNZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDNZp, PPC_INS_BDNZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZ, PPC_INS_BDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZ8, PPC_INS_BDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZA, PPC_INS_BDZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZAm, PPC_INS_BDZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZAp, PPC_INS_BDZA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZL, PPC_INS_BDZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLA, PPC_INS_BDZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLAm, PPC_INS_BDZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLAp, PPC_INS_BDZLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLR, PPC_INS_BDZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZLR8, PPC_INS_BDZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_LR8, PPC_REG_RM, 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZLRL, PPC_INS_BDZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLRLm, PPC_INS_BDZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLRLp, PPC_INS_BDZLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLRm, PPC_INS_BDZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZLRp, PPC_INS_BDZLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZLm, PPC_INS_BDZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZLp, PPC_INS_BDZL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BDZm, PPC_INS_BDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BDZp, PPC_INS_BDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BL, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL8, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL8_NOP, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL8_NOP_TLS, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL8_TLS, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL8_TLS_, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BLA, PPC_INS_BLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BLA8, PPC_INS_BLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BLA8_NOP, PPC_INS_BLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BLR, PPC_INS_BLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BLRL, PPC_INS_BLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BL_TLS, PPC_INS_BL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BRINC, PPC_INS_BRINC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_CMPD, PPC_INS_CMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPDI, PPC_INS_CMPDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPLD, PPC_INS_CMPLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPLDI, PPC_INS_CMPLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPLW, PPC_INS_CMPLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPLWI, PPC_INS_CMPLWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPW, PPC_INS_CMPW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CMPWI, PPC_INS_CMPWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CNTLZD, PPC_INS_CNTLZD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CNTLZDo, PPC_INS_CNTLZD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CNTLZW, PPC_INS_CNTLZW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CNTLZWo, PPC_INS_CNTLZW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CR6SET, PPC_INS_CREQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1EQ, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CR6UNSET, PPC_INS_CRXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1EQ, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRAND, PPC_INS_CRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRANDC, PPC_INS_CRANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CREQV, PPC_INS_CREQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRNAND, PPC_INS_CRNAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRNOR, PPC_INS_CRNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CROR, PPC_INS_CROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRORC, PPC_INS_CRORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRSET, PPC_INS_CREQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRUNSET, PPC_INS_CRXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_CRXOR, PPC_INS_CRXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBA, PPC_INS_DCBA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBF, PPC_INS_DCBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBI, PPC_INS_DCBI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBST, PPC_INS_DCBST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBT, PPC_INS_DCBT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBTST, PPC_INS_DCBTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBZ, PPC_INS_DCBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCBZL, PPC_INS_DCBZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DCCCI, PPC_INS_DCCCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_DIVD, PPC_INS_DIVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVDU, PPC_INS_DIVDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVDUo, PPC_INS_DIVDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVDo, PPC_INS_DIVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVW, PPC_INS_DIVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVWU, PPC_INS_DIVWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVWUo, PPC_INS_DIVWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DIVWo, PPC_INS_DIVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_DSS, PPC_INS_DSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSSALL, PPC_INS_DSSALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DST, PPC_INS_DST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DST64, PPC_INS_DST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTST, PPC_INS_DSTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTST64, PPC_INS_DSTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTSTT, PPC_INS_DSTSTT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTSTT64, PPC_INS_DSTSTT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTT, PPC_INS_DSTT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_DSTT64, PPC_INS_DSTT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_EIEIO, PPC_INS_EIEIO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EQV, PPC_INS_EQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EQV8, PPC_INS_EQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EQV8o, PPC_INS_EQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EQVo, PPC_INS_EQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EVABS, PPC_INS_EVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDIW, PPC_INS_EVADDIW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDSMIAAW, PPC_INS_EVADDSMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDSSIAAW, PPC_INS_EVADDSSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDUMIAAW, PPC_INS_EVADDUMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDUSIAAW, PPC_INS_EVADDUSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVADDW, PPC_INS_EVADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVAND, PPC_INS_EVAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVANDC, PPC_INS_EVANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCMPEQ, PPC_INS_EVCMPEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCMPGTS, PPC_INS_EVCMPGTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCMPGTU, PPC_INS_EVCMPGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCMPLTS, PPC_INS_EVCMPLTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCMPLTU, PPC_INS_EVCMPLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCNTLSW, PPC_INS_EVCNTLSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVCNTLZW, PPC_INS_EVCNTLZW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVDIVWS, PPC_INS_EVDIVWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVDIVWU, PPC_INS_EVDIVWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVEQV, PPC_INS_EVEQV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVEXTSB, PPC_INS_EVEXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVEXTSH, PPC_INS_EVEXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDD, PPC_INS_EVLDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDDX, PPC_INS_EVLDDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDH, PPC_INS_EVLDH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDHX, PPC_INS_EVLDHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDW, PPC_INS_EVLDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLDWX, PPC_INS_EVLDWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHESPLAT, PPC_INS_EVLHHESPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHESPLATX, PPC_INS_EVLHHESPLATX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHOSSPLAT, PPC_INS_EVLHHOSSPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHOSSPLATX, PPC_INS_EVLHHOSSPLATX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHOUSPLAT, PPC_INS_EVLHHOUSPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLHHOUSPLATX, PPC_INS_EVLHHOUSPLATX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHE, PPC_INS_EVLWHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHEX, PPC_INS_EVLWHEX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHOS, PPC_INS_EVLWHOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHOSX, PPC_INS_EVLWHOSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHOU, PPC_INS_EVLWHOU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHOUX, PPC_INS_EVLWHOUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHSPLAT, PPC_INS_EVLWHSPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWHSPLATX, PPC_INS_EVLWHSPLATX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWWSPLAT, PPC_INS_EVLWWSPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVLWWSPLATX, PPC_INS_EVLWWSPLATX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMERGEHI, PPC_INS_EVMERGEHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMERGEHILO, PPC_INS_EVMERGEHILO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMERGELO, PPC_INS_EVMERGELO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMERGELOHI, PPC_INS_EVMERGELOHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGSMFAA, PPC_INS_EVMHEGSMFAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGSMFAN, PPC_INS_EVMHEGSMFAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGSMIAA, PPC_INS_EVMHEGSMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGSMIAN, PPC_INS_EVMHEGSMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGUMIAA, PPC_INS_EVMHEGUMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEGUMIAN, PPC_INS_EVMHEGUMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMF, PPC_INS_EVMHESMF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMFA, PPC_INS_EVMHESMFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMFAAW, PPC_INS_EVMHESMFAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMFANW, PPC_INS_EVMHESMFANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMI, PPC_INS_EVMHESMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMIA, PPC_INS_EVMHESMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMIAAW, PPC_INS_EVMHESMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESMIANW, PPC_INS_EVMHESMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSF, PPC_INS_EVMHESSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSFA, PPC_INS_EVMHESSFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSFAAW, PPC_INS_EVMHESSFAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSFANW, PPC_INS_EVMHESSFANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSIAAW, PPC_INS_EVMHESSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHESSIANW, PPC_INS_EVMHESSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUMI, PPC_INS_EVMHEUMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUMIA, PPC_INS_EVMHEUMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUMIAAW, PPC_INS_EVMHEUMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUMIANW, PPC_INS_EVMHEUMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUSIAAW, PPC_INS_EVMHEUSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHEUSIANW, PPC_INS_EVMHEUSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGSMFAA, PPC_INS_EVMHOGSMFAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGSMFAN, PPC_INS_EVMHOGSMFAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGSMIAA, PPC_INS_EVMHOGSMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGSMIAN, PPC_INS_EVMHOGSMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGUMIAA, PPC_INS_EVMHOGUMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOGUMIAN, PPC_INS_EVMHOGUMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMF, PPC_INS_EVMHOSMF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMFA, PPC_INS_EVMHOSMFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMFAAW, PPC_INS_EVMHOSMFAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMFANW, PPC_INS_EVMHOSMFANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMI, PPC_INS_EVMHOSMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMIA, PPC_INS_EVMHOSMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMIAAW, PPC_INS_EVMHOSMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSMIANW, PPC_INS_EVMHOSMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSF, PPC_INS_EVMHOSSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSFA, PPC_INS_EVMHOSSFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSFAAW, PPC_INS_EVMHOSSFAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSFANW, PPC_INS_EVMHOSSFANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSIAAW, PPC_INS_EVMHOSSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOSSIANW, PPC_INS_EVMHOSSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUMI, PPC_INS_EVMHOUMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUMIA, PPC_INS_EVMHOUMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUMIAAW, PPC_INS_EVMHOUMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUMIANW, PPC_INS_EVMHOUMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUSIAAW, PPC_INS_EVMHOUSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMHOUSIANW, PPC_INS_EVMHOUSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMRA, PPC_INS_EVMRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSMF, PPC_INS_EVMWHSMF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSMFA, PPC_INS_EVMWHSMFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSMI, PPC_INS_EVMWHSMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSMIA, PPC_INS_EVMWHSMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSSF, PPC_INS_EVMWHSSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHSSFA, PPC_INS_EVMWHSSFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHUMI, PPC_INS_EVMWHUMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWHUMIA, PPC_INS_EVMWHUMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLSMIAAW, PPC_INS_EVMWLSMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLSMIANW, PPC_INS_EVMWLSMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLSSIAAW, PPC_INS_EVMWLSSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLSSIANW, PPC_INS_EVMWLSSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUMI, PPC_INS_EVMWLUMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUMIA, PPC_INS_EVMWLUMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUMIAAW, PPC_INS_EVMWLUMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUMIANW, PPC_INS_EVMWLUMIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUSIAAW, PPC_INS_EVMWLUSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWLUSIANW, PPC_INS_EVMWLUSIANW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMF, PPC_INS_EVMWSMF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMFA, PPC_INS_EVMWSMFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMFAA, PPC_INS_EVMWSMFAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMFAN, PPC_INS_EVMWSMFAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMI, PPC_INS_EVMWSMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMIA, PPC_INS_EVMWSMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMIAA, PPC_INS_EVMWSMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSMIAN, PPC_INS_EVMWSMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSSF, PPC_INS_EVMWSSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSSFA, PPC_INS_EVMWSSFA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSSFAA, PPC_INS_EVMWSSFAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWSSFAN, PPC_INS_EVMWSSFAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWUMI, PPC_INS_EVMWUMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWUMIA, PPC_INS_EVMWUMIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWUMIAA, PPC_INS_EVMWUMIAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVMWUMIAN, PPC_INS_EVMWUMIAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVNAND, PPC_INS_EVNAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVNEG, PPC_INS_EVNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVNOR, PPC_INS_EVNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVOR, PPC_INS_EVOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVORC, PPC_INS_EVORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVRLW, PPC_INS_EVRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVRLWI, PPC_INS_EVRLWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVRNDW, PPC_INS_EVRNDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSLW, PPC_INS_EVSLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSLWI, PPC_INS_EVSLWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSPLATFI, PPC_INS_EVSPLATFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSPLATI, PPC_INS_EVSPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSRWIS, PPC_INS_EVSRWIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSRWIU, PPC_INS_EVSRWIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSRWS, PPC_INS_EVSRWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSRWU, PPC_INS_EVSRWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDD, PPC_INS_EVSTDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDDX, PPC_INS_EVSTDDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDH, PPC_INS_EVSTDH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDHX, PPC_INS_EVSTDHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDW, PPC_INS_EVSTDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTDWX, PPC_INS_EVSTDWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWHE, PPC_INS_EVSTWHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWHEX, PPC_INS_EVSTWHEX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWHO, PPC_INS_EVSTWHO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWHOX, PPC_INS_EVSTWHOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWWE, PPC_INS_EVSTWWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWWEX, PPC_INS_EVSTWWEX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWWO, PPC_INS_EVSTWWO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSTWWOX, PPC_INS_EVSTWWOX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBFSMIAAW, PPC_INS_EVSUBFSMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBFSSIAAW, PPC_INS_EVSUBFSSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBFUMIAAW, PPC_INS_EVSUBFUMIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBFUSIAAW, PPC_INS_EVSUBFUSIAAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBFW, PPC_INS_EVSUBFW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVSUBIFW, PPC_INS_EVSUBIFW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EVXOR, PPC_INS_EVXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_SPE, 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSB, PPC_INS_EXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSB8, PPC_INS_EXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSB8_32_64, PPC_INS_EXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSB8o, PPC_INS_EXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSBo, PPC_INS_EXTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSH, PPC_INS_EXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSH8, PPC_INS_EXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSH8_32_64, PPC_INS_EXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSH8o, PPC_INS_EXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSHo, PPC_INS_EXTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSW, PPC_INS_EXTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSW_32_64, PPC_INS_EXTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSW_32_64o, PPC_INS_EXTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_EXTSWo, PPC_INS_EXTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FABSD, PPC_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FABSDo, PPC_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FABSS, PPC_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FABSSo, PPC_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FADD, PPC_INS_FADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FADDS, PPC_INS_FADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FADDSo, PPC_INS_FADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FADDo, PPC_INS_FADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFID, PPC_INS_FCFID,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDS, PPC_INS_FCFIDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDSo, PPC_INS_FCFIDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDU, PPC_INS_FCFIDU,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDUS, PPC_INS_FCFIDUS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDUSo, PPC_INS_FCFIDUS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDUo, PPC_INS_FCFIDU,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCFIDo, PPC_INS_FCFID,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCMPUD, PPC_INS_FCMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCMPUS, PPC_INS_FCMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCPSGND, PPC_INS_FCPSGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCPSGNDo, PPC_INS_FCPSGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCPSGNS, PPC_INS_FCPSGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCPSGNSo, PPC_INS_FCPSGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTID, PPC_INS_FCTID,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIDUZ, PPC_INS_FCTIDUZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIDUZo, PPC_INS_FCTIDUZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIDZ, PPC_INS_FCTIDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIDZo, PPC_INS_FCTIDZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIDo, PPC_INS_FCTID,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIW, PPC_INS_FCTIW,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIWUZ, PPC_INS_FCTIWUZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIWUZo, PPC_INS_FCTIWUZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIWZ, PPC_INS_FCTIWZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIWZo, PPC_INS_FCTIWZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FCTIWo, PPC_INS_FCTIW,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FDIV, PPC_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FDIVS, PPC_INS_FDIVS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FDIVSo, PPC_INS_FDIVS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FDIVo, PPC_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMADD, PPC_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMADDS, PPC_INS_FMADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMADDSo, PPC_INS_FMADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMADDo, PPC_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMR, PPC_INS_FMR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMRo, PPC_INS_FMR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMSUB, PPC_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMSUBS, PPC_INS_FMSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMSUBSo, PPC_INS_FMSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMSUBo, PPC_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMUL, PPC_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMULS, PPC_INS_FMULS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMULSo, PPC_INS_FMULS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FMULo, PPC_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNABSD, PPC_INS_FNABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNABSDo, PPC_INS_FNABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNABSS, PPC_INS_FNABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNABSSo, PPC_INS_FNABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNEGD, PPC_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNEGDo, PPC_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNEGS, PPC_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNEGSo, PPC_INS_FNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMADD, PPC_INS_FNMADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMADDS, PPC_INS_FNMADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMADDSo, PPC_INS_FNMADDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMADDo, PPC_INS_FNMADD,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMSUB, PPC_INS_FNMSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMSUBS, PPC_INS_FNMSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMSUBSo, PPC_INS_FNMSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FNMSUBo, PPC_INS_FNMSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRE, PPC_INS_FRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRES, PPC_INS_FRES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRESo, PPC_INS_FRES,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FREo, PPC_INS_FRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIMD, PPC_INS_FRIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIMDo, PPC_INS_FRIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIMS, PPC_INS_FRIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIMSo, PPC_INS_FRIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIND, PPC_INS_FRIN,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRINDo, PPC_INS_FRIN,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRINS, PPC_INS_FRIN,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRINSo, PPC_INS_FRIN,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIPD, PPC_INS_FRIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIPDo, PPC_INS_FRIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIPS, PPC_INS_FRIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIPSo, PPC_INS_FRIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIZD, PPC_INS_FRIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIZDo, PPC_INS_FRIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIZS, PPC_INS_FRIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRIZSo, PPC_INS_FRIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSP, PPC_INS_FRSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSPo, PPC_INS_FRSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSQRTE, PPC_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSQRTES, PPC_INS_FRSQRTES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSQRTESo, PPC_INS_FRSQRTES,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FRSQRTEo, PPC_INS_FRSQRTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSELD, PPC_INS_FSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSELDo, PPC_INS_FSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSELS, PPC_INS_FSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSELSo, PPC_INS_FSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSQRT, PPC_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSQRTS, PPC_INS_FSQRTS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSQRTSo, PPC_INS_FSQRTS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSQRTo, PPC_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSUB, PPC_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSUBS, PPC_INS_FSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSUBSo, PPC_INS_FSUBS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_FSUBo, PPC_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR1, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ICBI, PPC_INS_ICBI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ICCCI, PPC_INS_ICCCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_ISEL, PPC_INS_ISEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ISEL8, PPC_INS_ISEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ISYNC, PPC_INS_ISYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LA, PPC_INS_LA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZ, PPC_INS_LBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZ8, PPC_INS_LBZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZU, PPC_INS_LBZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZU8, PPC_INS_LBZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZUX, PPC_INS_LBZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZUX8, PPC_INS_LBZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZX, PPC_INS_LBZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LBZX8, PPC_INS_LBZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LD, PPC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDARX, PPC_INS_LDARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDBRX, PPC_INS_LDBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDU, PPC_INS_LDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDUX, PPC_INS_LDUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDX, PPC_INS_LDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LDinto_toc, PPC_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFD, PPC_INS_LFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFDU, PPC_INS_LFDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFDUX, PPC_INS_LFDUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFDX, PPC_INS_LFDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFIWAX, PPC_INS_LFIWAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFIWZX, PPC_INS_LFIWZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFS, PPC_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFSU, PPC_INS_LFSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFSUX, PPC_INS_LFSUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LFSX, PPC_INS_LFSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHA, PPC_INS_LHA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHA8, PPC_INS_LHA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAU, PPC_INS_LHAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAU8, PPC_INS_LHAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAUX, PPC_INS_LHAUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAUX8, PPC_INS_LHAUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAX, PPC_INS_LHAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHAX8, PPC_INS_LHAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHBRX, PPC_INS_LHBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZ, PPC_INS_LHZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZ8, PPC_INS_LHZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZU, PPC_INS_LHZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZU8, PPC_INS_LHZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZUX, PPC_INS_LHZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZUX8, PPC_INS_LHZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZX, PPC_INS_LHZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LHZX8, PPC_INS_LHZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LI, PPC_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LI8, PPC_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LIS, PPC_INS_LIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LIS8, PPC_INS_LIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LMW, PPC_INS_LMW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LSWI, PPC_INS_LSWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LVEBX, PPC_INS_LVEBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVEHX, PPC_INS_LVEHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVEWX, PPC_INS_LVEWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVSL, PPC_INS_LVSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVSR, PPC_INS_LVSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVX, PPC_INS_LVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LVXL, PPC_INS_LVXL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_LWA, PPC_INS_LWA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWARX, PPC_INS_LWARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWAUX, PPC_INS_LWAUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWAX, PPC_INS_LWAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWAX_32, PPC_INS_LWAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWA_32, PPC_INS_LWA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWBRX, PPC_INS_LWBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZ, PPC_INS_LWZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZ8, PPC_INS_LWZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZU, PPC_INS_LWZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZU8, PPC_INS_LWZU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZUX, PPC_INS_LWZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZUX8, PPC_INS_LWZUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZX, PPC_INS_LWZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LWZX8, PPC_INS_LWZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_LXSDX, PPC_INS_LXSDX,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_LXVD2X, PPC_INS_LXVD2X,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_LXVDSX, PPC_INS_LXVDSX,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_LXVW4X, PPC_INS_LXVW4X,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_MBAR, PPC_INS_MBAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_MCRF, PPC_INS_MCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFCR, PPC_INS_MFCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFCR8, PPC_INS_MFCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFCTR, PPC_INS_MFCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFCTR8, PPC_INS_MFCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFDCR, PPC_INS_MFDCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_MFFS, PPC_INS_MFFS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFLR, PPC_INS_MFLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFLR8, PPC_INS_MFLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR8, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFMSR, PPC_INS_MFMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFOCRF, PPC_INS_MFOCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFOCRF8, PPC_INS_MFOCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFSPR, PPC_INS_MFSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFSR, PPC_INS_MFSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFSRIN, PPC_INS_MFSRIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFTB, PPC_INS_MFTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFTB8, PPC_INS_MFSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFVRSAVE, PPC_INS_MFSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFVRSAVEv, PPC_INS_MFSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MFVSCR, PPC_INS_MFVSCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_MSYNC, PPC_INS_MSYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_MTCRF, PPC_INS_MTCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTCRF8, PPC_INS_MTCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTCTR, PPC_INS_MTCTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTCTR8, PPC_INS_MTCTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTCTR8loop, PPC_INS_MTCTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CTR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTCTRloop, PPC_INS_MTCTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTDCR, PPC_INS_MTDCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_MTFSB0, PPC_INS_MTFSB0,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_RM, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTFSB1, PPC_INS_MTFSB1,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_RM, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTFSF, PPC_INS_MTFSF,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_RM, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTLR, PPC_INS_MTLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTLR8, PPC_INS_MTLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_LR8, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTMSR, PPC_INS_MTMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTMSRD, PPC_INS_MTMSRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTOCRF, PPC_INS_MTOCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTOCRF8, PPC_INS_MTOCRF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTSPR, PPC_INS_MTSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTSR, PPC_INS_MTSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTSRIN, PPC_INS_MTSRIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTVRSAVE, PPC_INS_MTSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTVRSAVEv, PPC_INS_MTSPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MTVSCR, PPC_INS_MTVSCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_MULHD, PPC_INS_MULHD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHDU, PPC_INS_MULHDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHDUo, PPC_INS_MULHDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHDo, PPC_INS_MULHD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHW, PPC_INS_MULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHWU, PPC_INS_MULHWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHWUo, PPC_INS_MULHWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULHWo, PPC_INS_MULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLD, PPC_INS_MULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLDo, PPC_INS_MULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLI, PPC_INS_MULLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLI8, PPC_INS_MULLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLW, PPC_INS_MULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_MULLWo, PPC_INS_MULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NAND, PPC_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NAND8, PPC_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NAND8o, PPC_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NANDo, PPC_INS_NAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NEG, PPC_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NEG8, PPC_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NEG8o, PPC_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NEGo, PPC_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOP, PPC_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOP_GT_PWR6, PPC_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOP_GT_PWR7, PPC_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOR, PPC_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOR8, PPC_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NOR8o, PPC_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_NORo, PPC_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_OR, PPC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_OR8, PPC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_OR8o, PPC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORC, PPC_INS_ORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORC8, PPC_INS_ORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORC8o, PPC_INS_ORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORCo, PPC_INS_ORC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORI, PPC_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORI8, PPC_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORIS, PPC_INS_ORIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORIS8, PPC_INS_ORIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_ORo, PPC_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_POPCNTD, PPC_INS_POPCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_POPCNTW, PPC_INS_POPCNTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RFCI, PPC_INS_RFCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_RFDI, PPC_INS_RFDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_E500, 0 }, 0, 0
#endif
	},
	{
		PPC_RFI, PPC_INS_RFI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_RFID, PPC_INS_RFID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RFMCI, PPC_INS_RFMCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_E500, 0 }, 0, 0
#endif
	},
	{
		PPC_RLDCL, PPC_INS_RLDCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDCLo, PPC_INS_RLDCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDCR, PPC_INS_RLDCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDCRo, PPC_INS_RLDCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDIC, PPC_INS_RLDIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICL, PPC_INS_RLDICL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICL_32_64, PPC_INS_RLDICL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICLo, PPC_INS_RLDICL,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICR, PPC_INS_RLDICR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICRo, PPC_INS_RLDICR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDICo, PPC_INS_RLDIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDIMI, PPC_INS_RLDIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLDIMIo, PPC_INS_RLDIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWIMI, PPC_INS_RLWIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWIMI8, PPC_INS_RLWIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWIMI8o, PPC_INS_RLWIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWIMIo, PPC_INS_RLWIMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWINM, PPC_INS_RLWINM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWINM8, PPC_INS_RLWINM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWINM8o, PPC_INS_RLWINM,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWINMo, PPC_INS_RLWINM,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWNM, PPC_INS_RLWNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_RLWNMo, PPC_INS_RLWNM,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SC, PPC_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLBIA, PPC_INS_SLBIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLBIE, PPC_INS_SLBIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLBMFEE, PPC_INS_SLBMFEE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLBMTE, PPC_INS_SLBMTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLD, PPC_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLDo, PPC_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLW, PPC_INS_SLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SLWo, PPC_INS_SLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRAD, PPC_INS_SRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRADI, PPC_INS_SRADI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRADIo, PPC_INS_SRADI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRADo, PPC_INS_SRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRAW, PPC_INS_SRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRAWI, PPC_INS_SRAWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRAWIo, PPC_INS_SRAWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRAWo, PPC_INS_SRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRD, PPC_INS_SRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRDo, PPC_INS_SRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRW, PPC_INS_SRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SRWo, PPC_INS_SRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STB, PPC_INS_STB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STB8, PPC_INS_STB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBU, PPC_INS_STBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBU8, PPC_INS_STBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBUX, PPC_INS_STBUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBUX8, PPC_INS_STBUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBX, PPC_INS_STBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STBX8, PPC_INS_STBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STD, PPC_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STDBRX, PPC_INS_STDBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STDCX, PPC_INS_STDCX,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STDU, PPC_INS_STDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STDUX, PPC_INS_STDUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STDX, PPC_INS_STDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFD, PPC_INS_STFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFDU, PPC_INS_STFDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFDUX, PPC_INS_STFDUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFDX, PPC_INS_STFDX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFIWX, PPC_INS_STFIWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFS, PPC_INS_STFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFSU, PPC_INS_STFSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFSUX, PPC_INS_STFSUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STFSX, PPC_INS_STFSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STH, PPC_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STH8, PPC_INS_STH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHBRX, PPC_INS_STHBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHU, PPC_INS_STHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHU8, PPC_INS_STHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHUX, PPC_INS_STHUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHUX8, PPC_INS_STHUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHX, PPC_INS_STHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STHX8, PPC_INS_STHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STMW, PPC_INS_STMW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STSWI, PPC_INS_STSWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STVEBX, PPC_INS_STVEBX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_STVEHX, PPC_INS_STVEHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_STVEWX, PPC_INS_STVEWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_STVX, PPC_INS_STVX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_STVXL, PPC_INS_STVXL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_STW, PPC_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STW8, PPC_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWBRX, PPC_INS_STWBRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWCX, PPC_INS_STWCX,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWU, PPC_INS_STWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWU8, PPC_INS_STWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWUX, PPC_INS_STWUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWUX8, PPC_INS_STWUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWX, PPC_INS_STWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STWX8, PPC_INS_STWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_STXSDX, PPC_INS_STXSDX,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_STXVD2X, PPC_INS_STXVD2X,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_STXVW4X, PPC_INS_STXVW4X,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_SUBF, PPC_INS_SUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBF8, PPC_INS_SUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBF8o, PPC_INS_SUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFC, PPC_INS_SUBFC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFC8, PPC_INS_SUBFC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFC8o, PPC_INS_SUBFC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFCo, PPC_INS_SUBFC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFE, PPC_INS_SUBFE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFE8, PPC_INS_SUBFE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFE8o, PPC_INS_SUBFE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFEo, PPC_INS_SUBFE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFIC, PPC_INS_SUBFIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFIC8, PPC_INS_SUBFIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFME, PPC_INS_SUBFME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFME8, PPC_INS_SUBFME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFME8o, PPC_INS_SUBFME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFMEo, PPC_INS_SUBFME,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFZE, PPC_INS_SUBFZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFZE8, PPC_INS_SUBFZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFZE8o, PPC_INS_SUBFZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFZEo, PPC_INS_SUBFZE,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CARRY, 0 }, { PPC_REG_CARRY, PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SUBFo, PPC_INS_SUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_SYNC, PPC_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_NOTBOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_TAILB, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_TAILB8, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_TAILBA, PPC_INS_BA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_TAILBA8, PPC_INS_BA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_TAILBCTR, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_MODE32, 0 }, 1, 1
#endif
	},
	{
		PPC_TAILBCTR8, PPC_INS_BCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_TD, PPC_INS_TD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TDI, PPC_INS_TDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TLBIA, PPC_INS_TLBIA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TLBIE, PPC_INS_TLBIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TLBIEL, PPC_INS_TLBIEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TLBIVAX, PPC_INS_TLBIVAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBLD, PPC_INS_TLBLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC6XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBLI, PPC_INS_TLBLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC6XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBRE, PPC_INS_TLBRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBRE2, PPC_INS_TLBRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBSX, PPC_INS_TLBSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBSX2, PPC_INS_TLBSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBSX2D, PPC_INS_TLBSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBSYNC, PPC_INS_TLBSYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TLBWE, PPC_INS_TLBWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_TLBWE2, PPC_INS_TLBWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_PPC4XX, 0 }, 0, 0
#endif
	},
	{
		PPC_TRAP, PPC_INS_TRAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TW, PPC_INS_TW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_TWI, PPC_INS_TWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_VADDCUW, PPC_INS_VADDCUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDFP, PPC_INS_VADDFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDSBS, PPC_INS_VADDSBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDSHS, PPC_INS_VADDSHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDSWS, PPC_INS_VADDSWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUBM, PPC_INS_VADDUBM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUBS, PPC_INS_VADDUBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUHM, PPC_INS_VADDUHM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUHS, PPC_INS_VADDUHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUWM, PPC_INS_VADDUWM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VADDUWS, PPC_INS_VADDUWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAND, PPC_INS_VAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VANDC, PPC_INS_VANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGSB, PPC_INS_VAVGSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGSH, PPC_INS_VAVGSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGSW, PPC_INS_VAVGSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGUB, PPC_INS_VAVGUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGUH, PPC_INS_VAVGUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VAVGUW, PPC_INS_VAVGUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCFSX, PPC_INS_VCFSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCFSX_0, PPC_INS_VCFSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCFUX, PPC_INS_VCFUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCFUX_0, PPC_INS_VCFUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPBFP, PPC_INS_VCMPBFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPBFPo, PPC_INS_VCMPBFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQFP, PPC_INS_VCMPEQFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQFPo, PPC_INS_VCMPEQFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUB, PPC_INS_VCMPEQUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUBo, PPC_INS_VCMPEQUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUH, PPC_INS_VCMPEQUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUHo, PPC_INS_VCMPEQUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUW, PPC_INS_VCMPEQUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPEQUWo, PPC_INS_VCMPEQUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGEFP, PPC_INS_VCMPGEFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGEFPo, PPC_INS_VCMPGEFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTFP, PPC_INS_VCMPGTFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTFPo, PPC_INS_VCMPGTFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSB, PPC_INS_VCMPGTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSBo, PPC_INS_VCMPGTSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSH, PPC_INS_VCMPGTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSHo, PPC_INS_VCMPGTSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSW, PPC_INS_VCMPGTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTSWo, PPC_INS_VCMPGTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUB, PPC_INS_VCMPGTUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUBo, PPC_INS_VCMPGTUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUH, PPC_INS_VCMPGTUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUHo, PPC_INS_VCMPGTUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUW, PPC_INS_VCMPGTUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCMPGTUWo, PPC_INS_VCMPGTUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCTSXS, PPC_INS_VCTSXS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCTSXS_0, PPC_INS_VCTSXS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCTUXS, PPC_INS_VCTUXS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VCTUXS_0, PPC_INS_VCTUXS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VEXPTEFP, PPC_INS_VEXPTEFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VLOGEFP, PPC_INS_VLOGEFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMADDFP, PPC_INS_VMADDFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXFP, PPC_INS_VMAXFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXSB, PPC_INS_VMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXSH, PPC_INS_VMAXSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXSW, PPC_INS_VMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXUB, PPC_INS_VMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXUH, PPC_INS_VMAXUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMAXUW, PPC_INS_VMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMHADDSHS, PPC_INS_VMHADDSHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMHRADDSHS, PPC_INS_VMHRADDSHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINFP, PPC_INS_VMINFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINSB, PPC_INS_VMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINSH, PPC_INS_VMINSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINSW, PPC_INS_VMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINUB, PPC_INS_VMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINUH, PPC_INS_VMINUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMINUW, PPC_INS_VMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMLADDUHM, PPC_INS_VMLADDUHM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGHB, PPC_INS_VMRGHB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGHH, PPC_INS_VMRGHH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGHW, PPC_INS_VMRGHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGLB, PPC_INS_VMRGLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGLH, PPC_INS_VMRGLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMRGLW, PPC_INS_VMRGLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMMBM, PPC_INS_VMSUMMBM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMSHM, PPC_INS_VMSUMSHM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMSHS, PPC_INS_VMSUMSHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMUBM, PPC_INS_VMSUMUBM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMUHM, PPC_INS_VMSUMUHM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMSUMUHS, PPC_INS_VMSUMUHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULESB, PPC_INS_VMULESB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULESH, PPC_INS_VMULESH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULEUB, PPC_INS_VMULEUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULEUH, PPC_INS_VMULEUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULOSB, PPC_INS_VMULOSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULOSH, PPC_INS_VMULOSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULOUB, PPC_INS_VMULOUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VMULOUH, PPC_INS_VMULOUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VNMSUBFP, PPC_INS_VNMSUBFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VNOR, PPC_INS_VNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VOR, PPC_INS_VOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPERM, PPC_INS_VPERM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKPX, PPC_INS_VPKPX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKSHSS, PPC_INS_VPKSHSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKSHUS, PPC_INS_VPKSHUS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKSWSS, PPC_INS_VPKSWSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKSWUS, PPC_INS_VPKSWUS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKUHUM, PPC_INS_VPKUHUM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKUHUS, PPC_INS_VPKUHUS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKUWUM, PPC_INS_VPKUWUM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VPKUWUS, PPC_INS_VPKUWUS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VREFP, PPC_INS_VREFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRFIM, PPC_INS_VRFIM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRFIN, PPC_INS_VRFIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRFIP, PPC_INS_VRFIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRFIZ, PPC_INS_VRFIZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRLB, PPC_INS_VRLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRLH, PPC_INS_VRLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRLW, PPC_INS_VRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VRSQRTEFP, PPC_INS_VRSQRTEFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSEL, PPC_INS_VSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSL, PPC_INS_VSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSLB, PPC_INS_VSLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSLDOI, PPC_INS_VSLDOI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSLH, PPC_INS_VSLH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSLO, PPC_INS_VSLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSLW, PPC_INS_VSLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTB, PPC_INS_VSPLTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTH, PPC_INS_VSPLTH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTISB, PPC_INS_VSPLTISB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTISH, PPC_INS_VSPLTISH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTISW, PPC_INS_VSPLTISW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSPLTW, PPC_INS_VSPLTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSR, PPC_INS_VSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRAB, PPC_INS_VSRAB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRAH, PPC_INS_VSRAH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRAW, PPC_INS_VSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRB, PPC_INS_VSRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRH, PPC_INS_VSRH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRO, PPC_INS_VSRO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSRW, PPC_INS_VSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBCUW, PPC_INS_VSUBCUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBFP, PPC_INS_VSUBFP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBSBS, PPC_INS_VSUBSBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBSHS, PPC_INS_VSUBSHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBSWS, PPC_INS_VSUBSWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUBM, PPC_INS_VSUBUBM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUBS, PPC_INS_VSUBUBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUHM, PPC_INS_VSUBUHM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUHS, PPC_INS_VSUBUHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUWM, PPC_INS_VSUBUWM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUBUWS, PPC_INS_VSUBUWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUM2SWS, PPC_INS_VSUM2SWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUM4SBS, PPC_INS_VSUM4SBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUM4SHS, PPC_INS_VSUM4SHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUM4UBS, PPC_INS_VSUM4UBS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VSUMSWS, PPC_INS_VSUMSWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKHPX, PPC_INS_VUPKHPX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKHSB, PPC_INS_VUPKHSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKHSH, PPC_INS_VUPKHSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKLPX, PPC_INS_VUPKLPX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKLSB, PPC_INS_VUPKLSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VUPKLSH, PPC_INS_VUPKLSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_VXOR, PPC_INS_VXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SET0, PPC_INS_VXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SET0B, PPC_INS_VXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SET0H, PPC_INS_VXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SETALLONES, PPC_INS_VSPLTISW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SETALLONESB, PPC_INS_VSPLTISW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_V_SETALLONESH, PPC_INS_VSPLTISW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_ALTIVEC, 0 }, 0, 0
#endif
	},
	{
		PPC_WAIT, PPC_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_WRTEE, PPC_INS_WRTEE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_WRTEEI, PPC_INS_WRTEEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_BOOKE, 0 }, 0, 0
#endif
	},
	{
		PPC_XOR, PPC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XOR8, PPC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XOR8o, PPC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XORI, PPC_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XORI8, PPC_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XORIS, PPC_INS_XORIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XORIS8, PPC_INS_XORIS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XORo, PPC_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { PPC_REG_CR0, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_XSABSDP, PPC_INS_XSABSDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSADDDP, PPC_INS_XSADDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCMPODP, PPC_INS_XSCMPODP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCMPUDP, PPC_INS_XSCMPUDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCPSGNDP, PPC_INS_XSCPSGNDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVDPSP, PPC_INS_XSCVDPSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVDPSXDS, PPC_INS_XSCVDPSXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVDPSXWS, PPC_INS_XSCVDPSXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVDPUXDS, PPC_INS_XSCVDPUXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVDPUXWS, PPC_INS_XSCVDPUXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVSPDP, PPC_INS_XSCVSPDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVSXDDP, PPC_INS_XSCVSXDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSCVUXDDP, PPC_INS_XSCVUXDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSDIVDP, PPC_INS_XSDIVDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMADDADP, PPC_INS_XSMADDADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMADDMDP, PPC_INS_XSMADDMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMAXDP, PPC_INS_XSMAXDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMINDP, PPC_INS_XSMINDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMSUBADP, PPC_INS_XSMSUBADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMSUBMDP, PPC_INS_XSMSUBMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSMULDP, PPC_INS_XSMULDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNABSDP, PPC_INS_XSNABSDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNEGDP, PPC_INS_XSNEGDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNMADDADP, PPC_INS_XSNMADDADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNMADDMDP, PPC_INS_XSNMADDMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNMSUBADP, PPC_INS_XSNMSUBADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSNMSUBMDP, PPC_INS_XSNMSUBMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRDPI, PPC_INS_XSRDPI,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRDPIC, PPC_INS_XSRDPIC,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRDPIM, PPC_INS_XSRDPIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRDPIP, PPC_INS_XSRDPIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRDPIZ, PPC_INS_XSRDPIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSREDP, PPC_INS_XSREDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSRSQRTEDP, PPC_INS_XSRSQRTEDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSSQRTDP, PPC_INS_XSSQRTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSSUBDP, PPC_INS_XSSUBDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSTDIVDP, PPC_INS_XSTDIVDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XSTSQRTDP, PPC_INS_XSTSQRTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVABSDP, PPC_INS_XVABSDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVABSSP, PPC_INS_XVABSSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVADDDP, PPC_INS_XVADDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVADDSP, PPC_INS_XVADDSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPEQDP, PPC_INS_XVCMPEQDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPEQDPo, PPC_INS_XVCMPEQDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPEQSP, PPC_INS_XVCMPEQSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPEQSPo, PPC_INS_XVCMPEQSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGEDP, PPC_INS_XVCMPGEDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGEDPo, PPC_INS_XVCMPGEDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGESP, PPC_INS_XVCMPGESP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGESPo, PPC_INS_XVCMPGESP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGTDP, PPC_INS_XVCMPGTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGTDPo, PPC_INS_XVCMPGTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGTSP, PPC_INS_XVCMPGTSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCMPGTSPo, PPC_INS_XVCMPGTSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_CR6, 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCPSGNDP, PPC_INS_XVCPSGNDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCPSGNSP, PPC_INS_XVCPSGNSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVDPSP, PPC_INS_XVCVDPSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVDPSXDS, PPC_INS_XVCVDPSXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVDPSXWS, PPC_INS_XVCVDPSXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVDPUXDS, PPC_INS_XVCVDPUXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVDPUXWS, PPC_INS_XVCVDPUXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSPDP, PPC_INS_XVCVSPDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSPSXDS, PPC_INS_XVCVSPSXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSPSXWS, PPC_INS_XVCVSPSXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSPUXDS, PPC_INS_XVCVSPUXDS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSPUXWS, PPC_INS_XVCVSPUXWS,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSXDDP, PPC_INS_XVCVSXDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSXDSP, PPC_INS_XVCVSXDSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSXWDP, PPC_INS_XVCVSXWDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVSXWSP, PPC_INS_XVCVSXWSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVUXDDP, PPC_INS_XVCVUXDDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVUXDSP, PPC_INS_XVCVUXDSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVUXWDP, PPC_INS_XVCVUXWDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVCVUXWSP, PPC_INS_XVCVUXWSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVDIVDP, PPC_INS_XVDIVDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVDIVSP, PPC_INS_XVDIVSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMADDADP, PPC_INS_XVMADDADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMADDASP, PPC_INS_XVMADDASP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMADDMDP, PPC_INS_XVMADDMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMADDMSP, PPC_INS_XVMADDMSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMAXDP, PPC_INS_XVMAXDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMAXSP, PPC_INS_XVMAXSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMINDP, PPC_INS_XVMINDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMINSP, PPC_INS_XVMINSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMSUBADP, PPC_INS_XVMSUBADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMSUBASP, PPC_INS_XVMSUBASP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMSUBMDP, PPC_INS_XVMSUBMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMSUBMSP, PPC_INS_XVMSUBMSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMULDP, PPC_INS_XVMULDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVMULSP, PPC_INS_XVMULSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNABSDP, PPC_INS_XVNABSDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNABSSP, PPC_INS_XVNABSSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNEGDP, PPC_INS_XVNEGDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNEGSP, PPC_INS_XVNEGSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMADDADP, PPC_INS_XVNMADDADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMADDASP, PPC_INS_XVNMADDASP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMADDMDP, PPC_INS_XVNMADDMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMADDMSP, PPC_INS_XVNMADDMSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMSUBADP, PPC_INS_XVNMSUBADP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMSUBASP, PPC_INS_XVNMSUBASP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMSUBMDP, PPC_INS_XVNMSUBMDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVNMSUBMSP, PPC_INS_XVNMSUBMSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRDPI, PPC_INS_XVRDPI,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRDPIC, PPC_INS_XVRDPIC,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRDPIM, PPC_INS_XVRDPIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRDPIP, PPC_INS_XVRDPIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRDPIZ, PPC_INS_XVRDPIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVREDP, PPC_INS_XVREDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRESP, PPC_INS_XVRESP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSPI, PPC_INS_XVRSPI,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSPIC, PPC_INS_XVRSPIC,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSPIM, PPC_INS_XVRSPIM,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSPIP, PPC_INS_XVRSPIP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSPIZ, PPC_INS_XVRSPIZ,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSQRTEDP, PPC_INS_XVRSQRTEDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVRSQRTESP, PPC_INS_XVRSQRTESP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVSQRTDP, PPC_INS_XVSQRTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVSQRTSP, PPC_INS_XVSQRTSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVSUBDP, PPC_INS_XVSUBDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVSUBSP, PPC_INS_XVSUBSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVTDIVDP, PPC_INS_XVTDIVDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVTDIVSP, PPC_INS_XVTDIVSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVTSQRTDP, PPC_INS_XVTSQRTDP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XVTSQRTSP, PPC_INS_XVTSQRTSP,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLAND, PPC_INS_XXLAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLANDC, PPC_INS_XXLANDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLNOR, PPC_INS_XXLNOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLOR, PPC_INS_XXLOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLORf, PPC_INS_XXLOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXLXOR, PPC_INS_XXLXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXMRGHW, PPC_INS_XXMRGHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXMRGLW, PPC_INS_XXMRGLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXPERMDI, PPC_INS_XXPERMDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXSEL, PPC_INS_XXSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXSLDWI, PPC_INS_XXSLDWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_XXSPLTW, PPC_INS_XXSPLTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { PPC_GRP_VSX, 0 }, 0, 0
#endif
	},
	{
		PPC_gBC, PPC_INS_BC,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCA, PPC_INS_BCA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCCTR, PPC_INS_BCCTR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCCTRL, PPC_INS_BCCTRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCL, PPC_INS_BCL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCLA, PPC_INS_BCLA,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCLR, PPC_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_gBCLRL, PPC_INS_BCLRL,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, PPC_REG_CTR, 0 }, { 0 }, 0, 0
#endif
	},
};

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	int i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
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

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = PPC_GRP_JUMP;
				insn->detail->groups_count++;
			}

			insn->detail->ppc.update_cr0 = cs_reg_write((csh)&handle, insn, PPC_REG_CR0);
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[] = {
	{ PPC_INS_INVALID, NULL },

	{ PPC_INS_ADD, "add" },
	{ PPC_INS_ADDC, "addc" },
	{ PPC_INS_ADDE, "adde" },
	{ PPC_INS_ADDI, "addi" },
	{ PPC_INS_ADDIC, "addic" },
	{ PPC_INS_ADDIS, "addis" },
	{ PPC_INS_ADDME, "addme" },
	{ PPC_INS_ADDZE, "addze" },
	{ PPC_INS_AND, "and" },
	{ PPC_INS_ANDC, "andc" },
	{ PPC_INS_ANDIS, "andis" },
	{ PPC_INS_ANDI, "andi" },
	{ PPC_INS_B, "b" },
	{ PPC_INS_BA, "ba" },
	{ PPC_INS_BC, "bc" },
	{ PPC_INS_BCCTR, "bcctr" },
	{ PPC_INS_BCCTRL, "bcctrl" },
	{ PPC_INS_BCL, "bcl" },
	{ PPC_INS_BCLR, "bclr" },
	{ PPC_INS_BCLRL, "bclrl" },
	{ PPC_INS_BCTR, "bctr" },
	{ PPC_INS_BCTRL, "bctrl" },
	{ PPC_INS_BDNZ, "bdnz" },
	{ PPC_INS_BDNZA, "bdnza" },
	{ PPC_INS_BDNZL, "bdnzl" },
	{ PPC_INS_BDNZLA, "bdnzla" },
	{ PPC_INS_BDNZLR, "bdnzlr" },
	{ PPC_INS_BDNZLRL, "bdnzlrl" },
	{ PPC_INS_BDZ, "bdz" },
	{ PPC_INS_BDZA, "bdza" },
	{ PPC_INS_BDZL, "bdzl" },
	{ PPC_INS_BDZLA, "bdzla" },
	{ PPC_INS_BDZLR, "bdzlr" },
	{ PPC_INS_BDZLRL, "bdzlrl" },
	{ PPC_INS_BL, "bl" },
	{ PPC_INS_BLA, "bla" },
	{ PPC_INS_BLR, "blr" },
	{ PPC_INS_BLRL, "blrl" },
	{ PPC_INS_BRINC, "brinc" },
	{ PPC_INS_CMPD, "cmpd" },
	{ PPC_INS_CMPDI, "cmpdi" },
	{ PPC_INS_CMPLD, "cmpld" },
	{ PPC_INS_CMPLDI, "cmpldi" },
	{ PPC_INS_CMPLW, "cmplw" },
	{ PPC_INS_CMPLWI, "cmplwi" },
	{ PPC_INS_CMPW, "cmpw" },
	{ PPC_INS_CMPWI, "cmpwi" },
	{ PPC_INS_CNTLZD, "cntlzd" },
	{ PPC_INS_CNTLZW, "cntlzw" },
	{ PPC_INS_CREQV, "creqv" },
	{ PPC_INS_CRXOR, "crxor" },
	{ PPC_INS_CRAND, "crand" },
	{ PPC_INS_CRANDC, "crandc" },
	{ PPC_INS_CRNAND, "crnand" },
	{ PPC_INS_CRNOR, "crnor" },
	{ PPC_INS_CROR, "cror" },
	{ PPC_INS_CRORC, "crorc" },
	{ PPC_INS_DCBA, "dcba" },
	{ PPC_INS_DCBF, "dcbf" },
	{ PPC_INS_DCBI, "dcbi" },
	{ PPC_INS_DCBST, "dcbst" },
	{ PPC_INS_DCBT, "dcbt" },
	{ PPC_INS_DCBTST, "dcbtst" },
	{ PPC_INS_DCBZ, "dcbz" },
	{ PPC_INS_DCBZL, "dcbzl" },
	{ PPC_INS_DCCCI, "dccci" },
	{ PPC_INS_DIVD, "divd" },
	{ PPC_INS_DIVDU, "divdu" },
	{ PPC_INS_DIVW, "divw" },
	{ PPC_INS_DIVWU, "divwu" },
	{ PPC_INS_DSS, "dss" },
	{ PPC_INS_DSSALL, "dssall" },
	{ PPC_INS_DST, "dst" },
	{ PPC_INS_DSTST, "dstst" },
	{ PPC_INS_DSTSTT, "dststt" },
	{ PPC_INS_DSTT, "dstt" },
	{ PPC_INS_EIEIO, "eieio" },
	{ PPC_INS_EQV, "eqv" },
	{ PPC_INS_EVABS, "evabs" },
	{ PPC_INS_EVADDIW, "evaddiw" },
	{ PPC_INS_EVADDSMIAAW, "evaddsmiaaw" },
	{ PPC_INS_EVADDSSIAAW, "evaddssiaaw" },
	{ PPC_INS_EVADDUMIAAW, "evaddumiaaw" },
	{ PPC_INS_EVADDUSIAAW, "evaddusiaaw" },
	{ PPC_INS_EVADDW, "evaddw" },
	{ PPC_INS_EVAND, "evand" },
	{ PPC_INS_EVANDC, "evandc" },
	{ PPC_INS_EVCMPEQ, "evcmpeq" },
	{ PPC_INS_EVCMPGTS, "evcmpgts" },
	{ PPC_INS_EVCMPGTU, "evcmpgtu" },
	{ PPC_INS_EVCMPLTS, "evcmplts" },
	{ PPC_INS_EVCMPLTU, "evcmpltu" },
	{ PPC_INS_EVCNTLSW, "evcntlsw" },
	{ PPC_INS_EVCNTLZW, "evcntlzw" },
	{ PPC_INS_EVDIVWS, "evdivws" },
	{ PPC_INS_EVDIVWU, "evdivwu" },
	{ PPC_INS_EVEQV, "eveqv" },
	{ PPC_INS_EVEXTSB, "evextsb" },
	{ PPC_INS_EVEXTSH, "evextsh" },
	{ PPC_INS_EVLDD, "evldd" },
	{ PPC_INS_EVLDDX, "evlddx" },
	{ PPC_INS_EVLDH, "evldh" },
	{ PPC_INS_EVLDHX, "evldhx" },
	{ PPC_INS_EVLDW, "evldw" },
	{ PPC_INS_EVLDWX, "evldwx" },
	{ PPC_INS_EVLHHESPLAT, "evlhhesplat" },
	{ PPC_INS_EVLHHESPLATX, "evlhhesplatx" },
	{ PPC_INS_EVLHHOSSPLAT, "evlhhossplat" },
	{ PPC_INS_EVLHHOSSPLATX, "evlhhossplatx" },
	{ PPC_INS_EVLHHOUSPLAT, "evlhhousplat" },
	{ PPC_INS_EVLHHOUSPLATX, "evlhhousplatx" },
	{ PPC_INS_EVLWHE, "evlwhe" },
	{ PPC_INS_EVLWHEX, "evlwhex" },
	{ PPC_INS_EVLWHOS, "evlwhos" },
	{ PPC_INS_EVLWHOSX, "evlwhosx" },
	{ PPC_INS_EVLWHOU, "evlwhou" },
	{ PPC_INS_EVLWHOUX, "evlwhoux" },
	{ PPC_INS_EVLWHSPLAT, "evlwhsplat" },
	{ PPC_INS_EVLWHSPLATX, "evlwhsplatx" },
	{ PPC_INS_EVLWWSPLAT, "evlwwsplat" },
	{ PPC_INS_EVLWWSPLATX, "evlwwsplatx" },
	{ PPC_INS_EVMERGEHI, "evmergehi" },
	{ PPC_INS_EVMERGEHILO, "evmergehilo" },
	{ PPC_INS_EVMERGELO, "evmergelo" },
	{ PPC_INS_EVMERGELOHI, "evmergelohi" },
	{ PPC_INS_EVMHEGSMFAA, "evmhegsmfaa" },
	{ PPC_INS_EVMHEGSMFAN, "evmhegsmfan" },
	{ PPC_INS_EVMHEGSMIAA, "evmhegsmiaa" },
	{ PPC_INS_EVMHEGSMIAN, "evmhegsmian" },
	{ PPC_INS_EVMHEGUMIAA, "evmhegumiaa" },
	{ PPC_INS_EVMHEGUMIAN, "evmhegumian" },
	{ PPC_INS_EVMHESMF, "evmhesmf" },
	{ PPC_INS_EVMHESMFA, "evmhesmfa" },
	{ PPC_INS_EVMHESMFAAW, "evmhesmfaaw" },
	{ PPC_INS_EVMHESMFANW, "evmhesmfanw" },
	{ PPC_INS_EVMHESMI, "evmhesmi" },
	{ PPC_INS_EVMHESMIA, "evmhesmia" },
	{ PPC_INS_EVMHESMIAAW, "evmhesmiaaw" },
	{ PPC_INS_EVMHESMIANW, "evmhesmianw" },
	{ PPC_INS_EVMHESSF, "evmhessf" },
	{ PPC_INS_EVMHESSFA, "evmhessfa" },
	{ PPC_INS_EVMHESSFAAW, "evmhessfaaw" },
	{ PPC_INS_EVMHESSFANW, "evmhessfanw" },
	{ PPC_INS_EVMHESSIAAW, "evmhessiaaw" },
	{ PPC_INS_EVMHESSIANW, "evmhessianw" },
	{ PPC_INS_EVMHEUMI, "evmheumi" },
	{ PPC_INS_EVMHEUMIA, "evmheumia" },
	{ PPC_INS_EVMHEUMIAAW, "evmheumiaaw" },
	{ PPC_INS_EVMHEUMIANW, "evmheumianw" },
	{ PPC_INS_EVMHEUSIAAW, "evmheusiaaw" },
	{ PPC_INS_EVMHEUSIANW, "evmheusianw" },
	{ PPC_INS_EVMHOGSMFAA, "evmhogsmfaa" },
	{ PPC_INS_EVMHOGSMFAN, "evmhogsmfan" },
	{ PPC_INS_EVMHOGSMIAA, "evmhogsmiaa" },
	{ PPC_INS_EVMHOGSMIAN, "evmhogsmian" },
	{ PPC_INS_EVMHOGUMIAA, "evmhogumiaa" },
	{ PPC_INS_EVMHOGUMIAN, "evmhogumian" },
	{ PPC_INS_EVMHOSMF, "evmhosmf" },
	{ PPC_INS_EVMHOSMFA, "evmhosmfa" },
	{ PPC_INS_EVMHOSMFAAW, "evmhosmfaaw" },
	{ PPC_INS_EVMHOSMFANW, "evmhosmfanw" },
	{ PPC_INS_EVMHOSMI, "evmhosmi" },
	{ PPC_INS_EVMHOSMIA, "evmhosmia" },
	{ PPC_INS_EVMHOSMIAAW, "evmhosmiaaw" },
	{ PPC_INS_EVMHOSMIANW, "evmhosmianw" },
	{ PPC_INS_EVMHOSSF, "evmhossf" },
	{ PPC_INS_EVMHOSSFA, "evmhossfa" },
	{ PPC_INS_EVMHOSSFAAW, "evmhossfaaw" },
	{ PPC_INS_EVMHOSSFANW, "evmhossfanw" },
	{ PPC_INS_EVMHOSSIAAW, "evmhossiaaw" },
	{ PPC_INS_EVMHOSSIANW, "evmhossianw" },
	{ PPC_INS_EVMHOUMI, "evmhoumi" },
	{ PPC_INS_EVMHOUMIA, "evmhoumia" },
	{ PPC_INS_EVMHOUMIAAW, "evmhoumiaaw" },
	{ PPC_INS_EVMHOUMIANW, "evmhoumianw" },
	{ PPC_INS_EVMHOUSIAAW, "evmhousiaaw" },
	{ PPC_INS_EVMHOUSIANW, "evmhousianw" },
	{ PPC_INS_EVMRA, "evmra" },
	{ PPC_INS_EVMWHSMF, "evmwhsmf" },
	{ PPC_INS_EVMWHSMFA, "evmwhsmfa" },
	{ PPC_INS_EVMWHSMI, "evmwhsmi" },
	{ PPC_INS_EVMWHSMIA, "evmwhsmia" },
	{ PPC_INS_EVMWHSSF, "evmwhssf" },
	{ PPC_INS_EVMWHSSFA, "evmwhssfa" },
	{ PPC_INS_EVMWHUMI, "evmwhumi" },
	{ PPC_INS_EVMWHUMIA, "evmwhumia" },
	{ PPC_INS_EVMWLSMIAAW, "evmwlsmiaaw" },
	{ PPC_INS_EVMWLSMIANW, "evmwlsmianw" },
	{ PPC_INS_EVMWLSSIAAW, "evmwlssiaaw" },
	{ PPC_INS_EVMWLSSIANW, "evmwlssianw" },
	{ PPC_INS_EVMWLUMI, "evmwlumi" },
	{ PPC_INS_EVMWLUMIA, "evmwlumia" },
	{ PPC_INS_EVMWLUMIAAW, "evmwlumiaaw" },
	{ PPC_INS_EVMWLUMIANW, "evmwlumianw" },
	{ PPC_INS_EVMWLUSIAAW, "evmwlusiaaw" },
	{ PPC_INS_EVMWLUSIANW, "evmwlusianw" },
	{ PPC_INS_EVMWSMF, "evmwsmf" },
	{ PPC_INS_EVMWSMFA, "evmwsmfa" },
	{ PPC_INS_EVMWSMFAA, "evmwsmfaa" },
	{ PPC_INS_EVMWSMFAN, "evmwsmfan" },
	{ PPC_INS_EVMWSMI, "evmwsmi" },
	{ PPC_INS_EVMWSMIA, "evmwsmia" },
	{ PPC_INS_EVMWSMIAA, "evmwsmiaa" },
	{ PPC_INS_EVMWSMIAN, "evmwsmian" },
	{ PPC_INS_EVMWSSF, "evmwssf" },
	{ PPC_INS_EVMWSSFA, "evmwssfa" },
	{ PPC_INS_EVMWSSFAA, "evmwssfaa" },
	{ PPC_INS_EVMWSSFAN, "evmwssfan" },
	{ PPC_INS_EVMWUMI, "evmwumi" },
	{ PPC_INS_EVMWUMIA, "evmwumia" },
	{ PPC_INS_EVMWUMIAA, "evmwumiaa" },
	{ PPC_INS_EVMWUMIAN, "evmwumian" },
	{ PPC_INS_EVNAND, "evnand" },
	{ PPC_INS_EVNEG, "evneg" },
	{ PPC_INS_EVNOR, "evnor" },
	{ PPC_INS_EVOR, "evor" },
	{ PPC_INS_EVORC, "evorc" },
	{ PPC_INS_EVRLW, "evrlw" },
	{ PPC_INS_EVRLWI, "evrlwi" },
	{ PPC_INS_EVRNDW, "evrndw" },
	{ PPC_INS_EVSLW, "evslw" },
	{ PPC_INS_EVSLWI, "evslwi" },
	{ PPC_INS_EVSPLATFI, "evsplatfi" },
	{ PPC_INS_EVSPLATI, "evsplati" },
	{ PPC_INS_EVSRWIS, "evsrwis" },
	{ PPC_INS_EVSRWIU, "evsrwiu" },
	{ PPC_INS_EVSRWS, "evsrws" },
	{ PPC_INS_EVSRWU, "evsrwu" },
	{ PPC_INS_EVSTDD, "evstdd" },
	{ PPC_INS_EVSTDDX, "evstddx" },
	{ PPC_INS_EVSTDH, "evstdh" },
	{ PPC_INS_EVSTDHX, "evstdhx" },
	{ PPC_INS_EVSTDW, "evstdw" },
	{ PPC_INS_EVSTDWX, "evstdwx" },
	{ PPC_INS_EVSTWHE, "evstwhe" },
	{ PPC_INS_EVSTWHEX, "evstwhex" },
	{ PPC_INS_EVSTWHO, "evstwho" },
	{ PPC_INS_EVSTWHOX, "evstwhox" },
	{ PPC_INS_EVSTWWE, "evstwwe" },
	{ PPC_INS_EVSTWWEX, "evstwwex" },
	{ PPC_INS_EVSTWWO, "evstwwo" },
	{ PPC_INS_EVSTWWOX, "evstwwox" },
	{ PPC_INS_EVSUBFSMIAAW, "evsubfsmiaaw" },
	{ PPC_INS_EVSUBFSSIAAW, "evsubfssiaaw" },
	{ PPC_INS_EVSUBFUMIAAW, "evsubfumiaaw" },
	{ PPC_INS_EVSUBFUSIAAW, "evsubfusiaaw" },
	{ PPC_INS_EVSUBFW, "evsubfw" },
	{ PPC_INS_EVSUBIFW, "evsubifw" },
	{ PPC_INS_EVXOR, "evxor" },
	{ PPC_INS_EXTSB, "extsb" },
	{ PPC_INS_EXTSH, "extsh" },
	{ PPC_INS_EXTSW, "extsw" },
	{ PPC_INS_FABS, "fabs" },
	{ PPC_INS_FADD, "fadd" },
	{ PPC_INS_FADDS, "fadds" },
	{ PPC_INS_FCFID, "fcfid" },
	{ PPC_INS_FCFIDS, "fcfids" },
	{ PPC_INS_FCFIDU, "fcfidu" },
	{ PPC_INS_FCFIDUS, "fcfidus" },
	{ PPC_INS_FCMPU, "fcmpu" },
	{ PPC_INS_FCPSGN, "fcpsgn" },
	{ PPC_INS_FCTID, "fctid" },
	{ PPC_INS_FCTIDUZ, "fctiduz" },
	{ PPC_INS_FCTIDZ, "fctidz" },
	{ PPC_INS_FCTIW, "fctiw" },
	{ PPC_INS_FCTIWUZ, "fctiwuz" },
	{ PPC_INS_FCTIWZ, "fctiwz" },
	{ PPC_INS_FDIV, "fdiv" },
	{ PPC_INS_FDIVS, "fdivs" },
	{ PPC_INS_FMADD, "fmadd" },
	{ PPC_INS_FMADDS, "fmadds" },
	{ PPC_INS_FMR, "fmr" },
	{ PPC_INS_FMSUB, "fmsub" },
	{ PPC_INS_FMSUBS, "fmsubs" },
	{ PPC_INS_FMUL, "fmul" },
	{ PPC_INS_FMULS, "fmuls" },
	{ PPC_INS_FNABS, "fnabs" },
	{ PPC_INS_FNEG, "fneg" },
	{ PPC_INS_FNMADD, "fnmadd" },
	{ PPC_INS_FNMADDS, "fnmadds" },
	{ PPC_INS_FNMSUB, "fnmsub" },
	{ PPC_INS_FNMSUBS, "fnmsubs" },
	{ PPC_INS_FRE, "fre" },
	{ PPC_INS_FRES, "fres" },
	{ PPC_INS_FRIM, "frim" },
	{ PPC_INS_FRIN, "frin" },
	{ PPC_INS_FRIP, "frip" },
	{ PPC_INS_FRIZ, "friz" },
	{ PPC_INS_FRSP, "frsp" },
	{ PPC_INS_FRSQRTE, "frsqrte" },
	{ PPC_INS_FRSQRTES, "frsqrtes" },
	{ PPC_INS_FSEL, "fsel" },
	{ PPC_INS_FSQRT, "fsqrt" },
	{ PPC_INS_FSQRTS, "fsqrts" },
	{ PPC_INS_FSUB, "fsub" },
	{ PPC_INS_FSUBS, "fsubs" },
	{ PPC_INS_ICBI, "icbi" },
	{ PPC_INS_ICCCI, "iccci" },
	{ PPC_INS_ISEL, "isel" },
	{ PPC_INS_ISYNC, "isync" },
	{ PPC_INS_LA, "la" },
	{ PPC_INS_LBZ, "lbz" },
	{ PPC_INS_LBZU, "lbzu" },
	{ PPC_INS_LBZUX, "lbzux" },
	{ PPC_INS_LBZX, "lbzx" },
	{ PPC_INS_LD, "ld" },
	{ PPC_INS_LDARX, "ldarx" },
	{ PPC_INS_LDBRX, "ldbrx" },
	{ PPC_INS_LDU, "ldu" },
	{ PPC_INS_LDUX, "ldux" },
	{ PPC_INS_LDX, "ldx" },
	{ PPC_INS_LFD, "lfd" },
	{ PPC_INS_LFDU, "lfdu" },
	{ PPC_INS_LFDUX, "lfdux" },
	{ PPC_INS_LFDX, "lfdx" },
	{ PPC_INS_LFIWAX, "lfiwax" },
	{ PPC_INS_LFIWZX, "lfiwzx" },
	{ PPC_INS_LFS, "lfs" },
	{ PPC_INS_LFSU, "lfsu" },
	{ PPC_INS_LFSUX, "lfsux" },
	{ PPC_INS_LFSX, "lfsx" },
	{ PPC_INS_LHA, "lha" },
	{ PPC_INS_LHAU, "lhau" },
	{ PPC_INS_LHAUX, "lhaux" },
	{ PPC_INS_LHAX, "lhax" },
	{ PPC_INS_LHBRX, "lhbrx" },
	{ PPC_INS_LHZ, "lhz" },
	{ PPC_INS_LHZU, "lhzu" },
	{ PPC_INS_LHZUX, "lhzux" },
	{ PPC_INS_LHZX, "lhzx" },
	{ PPC_INS_LI, "li" },
	{ PPC_INS_LIS, "lis" },
	{ PPC_INS_LMW, "lmw" },
	{ PPC_INS_LSWI, "lswi" },
	{ PPC_INS_LVEBX, "lvebx" },
	{ PPC_INS_LVEHX, "lvehx" },
	{ PPC_INS_LVEWX, "lvewx" },
	{ PPC_INS_LVSL, "lvsl" },
	{ PPC_INS_LVSR, "lvsr" },
	{ PPC_INS_LVX, "lvx" },
	{ PPC_INS_LVXL, "lvxl" },
	{ PPC_INS_LWA, "lwa" },
	{ PPC_INS_LWARX, "lwarx" },
	{ PPC_INS_LWAUX, "lwaux" },
	{ PPC_INS_LWAX, "lwax" },
	{ PPC_INS_LWBRX, "lwbrx" },
	{ PPC_INS_LWZ, "lwz" },
	{ PPC_INS_LWZU, "lwzu" },
	{ PPC_INS_LWZUX, "lwzux" },
	{ PPC_INS_LWZX, "lwzx" },
	{ PPC_INS_LXSDX, "lxsdx" },
	{ PPC_INS_LXVD2X, "lxvd2x" },
	{ PPC_INS_LXVDSX, "lxvdsx" },
	{ PPC_INS_LXVW4X, "lxvw4x" },
	{ PPC_INS_MBAR, "mbar" },
	{ PPC_INS_MCRF, "mcrf" },
	{ PPC_INS_MFCR, "mfcr" },
	{ PPC_INS_MFCTR, "mfctr" },
	{ PPC_INS_MFDCR, "mfdcr" },
	{ PPC_INS_MFFS, "mffs" },
	{ PPC_INS_MFLR, "mflr" },
	{ PPC_INS_MFMSR, "mfmsr" },
	{ PPC_INS_MFOCRF, "mfocrf" },
	{ PPC_INS_MFSPR, "mfspr" },
	{ PPC_INS_MFSR, "mfsr" },
	{ PPC_INS_MFSRIN, "mfsrin" },
	{ PPC_INS_MFTB, "mftb" },
	{ PPC_INS_MFVSCR, "mfvscr" },
	{ PPC_INS_MSYNC, "msync" },
	{ PPC_INS_MTCRF, "mtcrf" },
	{ PPC_INS_MTCTR, "mtctr" },
	{ PPC_INS_MTDCR, "mtdcr" },
	{ PPC_INS_MTFSB0, "mtfsb0" },
	{ PPC_INS_MTFSB1, "mtfsb1" },
	{ PPC_INS_MTFSF, "mtfsf" },
	{ PPC_INS_MTLR, "mtlr" },
	{ PPC_INS_MTMSR, "mtmsr" },
	{ PPC_INS_MTMSRD, "mtmsrd" },
	{ PPC_INS_MTOCRF, "mtocrf" },
	{ PPC_INS_MTSPR, "mtspr" },
	{ PPC_INS_MTSR, "mtsr" },
	{ PPC_INS_MTSRIN, "mtsrin" },
	{ PPC_INS_MTVSCR, "mtvscr" },
	{ PPC_INS_MULHD, "mulhd" },
	{ PPC_INS_MULHDU, "mulhdu" },
	{ PPC_INS_MULHW, "mulhw" },
	{ PPC_INS_MULHWU, "mulhwu" },
	{ PPC_INS_MULLD, "mulld" },
	{ PPC_INS_MULLI, "mulli" },
	{ PPC_INS_MULLW, "mullw" },
	{ PPC_INS_NAND, "nand" },
	{ PPC_INS_NEG, "neg" },
	{ PPC_INS_NOP, "nop" },
	{ PPC_INS_ORI, "ori" },
	{ PPC_INS_NOR, "nor" },
	{ PPC_INS_OR, "or" },
	{ PPC_INS_ORC, "orc" },
	{ PPC_INS_ORIS, "oris" },
	{ PPC_INS_POPCNTD, "popcntd" },
	{ PPC_INS_POPCNTW, "popcntw" },
	{ PPC_INS_RFCI, "rfci" },
	{ PPC_INS_RFDI, "rfdi" },
	{ PPC_INS_RFI, "rfi" },
	{ PPC_INS_RFID, "rfid" },
	{ PPC_INS_RFMCI, "rfmci" },
	{ PPC_INS_RLDCL, "rldcl" },
	{ PPC_INS_RLDCR, "rldcr" },
	{ PPC_INS_RLDIC, "rldic" },
	{ PPC_INS_RLDICL, "rldicl" },
	{ PPC_INS_RLDICR, "rldicr" },
	{ PPC_INS_RLDIMI, "rldimi" },
	{ PPC_INS_RLWIMI, "rlwimi" },
	{ PPC_INS_RLWINM, "rlwinm" },
	{ PPC_INS_RLWNM, "rlwnm" },
	{ PPC_INS_SC, "sc" },
	{ PPC_INS_SLBIA, "slbia" },
	{ PPC_INS_SLBIE, "slbie" },
	{ PPC_INS_SLBMFEE, "slbmfee" },
	{ PPC_INS_SLBMTE, "slbmte" },
	{ PPC_INS_SLD, "sld" },
	{ PPC_INS_SLW, "slw" },
	{ PPC_INS_SRAD, "srad" },
	{ PPC_INS_SRADI, "sradi" },
	{ PPC_INS_SRAW, "sraw" },
	{ PPC_INS_SRAWI, "srawi" },
	{ PPC_INS_SRD, "srd" },
	{ PPC_INS_SRW, "srw" },
	{ PPC_INS_STB, "stb" },
	{ PPC_INS_STBU, "stbu" },
	{ PPC_INS_STBUX, "stbux" },
	{ PPC_INS_STBX, "stbx" },
	{ PPC_INS_STD, "std" },
	{ PPC_INS_STDBRX, "stdbrx" },
	{ PPC_INS_STDCX, "stdcx" },
	{ PPC_INS_STDU, "stdu" },
	{ PPC_INS_STDUX, "stdux" },
	{ PPC_INS_STDX, "stdx" },
	{ PPC_INS_STFD, "stfd" },
	{ PPC_INS_STFDU, "stfdu" },
	{ PPC_INS_STFDUX, "stfdux" },
	{ PPC_INS_STFDX, "stfdx" },
	{ PPC_INS_STFIWX, "stfiwx" },
	{ PPC_INS_STFS, "stfs" },
	{ PPC_INS_STFSU, "stfsu" },
	{ PPC_INS_STFSUX, "stfsux" },
	{ PPC_INS_STFSX, "stfsx" },
	{ PPC_INS_STH, "sth" },
	{ PPC_INS_STHBRX, "sthbrx" },
	{ PPC_INS_STHU, "sthu" },
	{ PPC_INS_STHUX, "sthux" },
	{ PPC_INS_STHX, "sthx" },
	{ PPC_INS_STMW, "stmw" },
	{ PPC_INS_STSWI, "stswi" },
	{ PPC_INS_STVEBX, "stvebx" },
	{ PPC_INS_STVEHX, "stvehx" },
	{ PPC_INS_STVEWX, "stvewx" },
	{ PPC_INS_STVX, "stvx" },
	{ PPC_INS_STVXL, "stvxl" },
	{ PPC_INS_STW, "stw" },
	{ PPC_INS_STWBRX, "stwbrx" },
	{ PPC_INS_STWCX, "stwcx" },
	{ PPC_INS_STWU, "stwu" },
	{ PPC_INS_STWUX, "stwux" },
	{ PPC_INS_STWX, "stwx" },
	{ PPC_INS_STXSDX, "stxsdx" },
	{ PPC_INS_STXVD2X, "stxvd2x" },
	{ PPC_INS_STXVW4X, "stxvw4x" },
	{ PPC_INS_SUBF, "subf" },
	{ PPC_INS_SUBFC, "subfc" },
	{ PPC_INS_SUBFE, "subfe" },
	{ PPC_INS_SUBFIC, "subfic" },
	{ PPC_INS_SUBFME, "subfme" },
	{ PPC_INS_SUBFZE, "subfze" },
	{ PPC_INS_SYNC, "sync" },
	{ PPC_INS_TD, "td" },
	{ PPC_INS_TDI, "tdi" },
	{ PPC_INS_TLBIA, "tlbia" },
	{ PPC_INS_TLBIE, "tlbie" },
	{ PPC_INS_TLBIEL, "tlbiel" },
	{ PPC_INS_TLBIVAX, "tlbivax" },
	{ PPC_INS_TLBLD, "tlbld" },
	{ PPC_INS_TLBLI, "tlbli" },
	{ PPC_INS_TLBRE, "tlbre" },
	{ PPC_INS_TLBSX, "tlbsx" },
	{ PPC_INS_TLBSYNC, "tlbsync" },
	{ PPC_INS_TLBWE, "tlbwe" },
	{ PPC_INS_TRAP, "trap" },
	{ PPC_INS_TW, "tw" },
	{ PPC_INS_TWI, "twi" },
	{ PPC_INS_VADDCUW, "vaddcuw" },
	{ PPC_INS_VADDFP, "vaddfp" },
	{ PPC_INS_VADDSBS, "vaddsbs" },
	{ PPC_INS_VADDSHS, "vaddshs" },
	{ PPC_INS_VADDSWS, "vaddsws" },
	{ PPC_INS_VADDUBM, "vaddubm" },
	{ PPC_INS_VADDUBS, "vaddubs" },
	{ PPC_INS_VADDUHM, "vadduhm" },
	{ PPC_INS_VADDUHS, "vadduhs" },
	{ PPC_INS_VADDUWM, "vadduwm" },
	{ PPC_INS_VADDUWS, "vadduws" },
	{ PPC_INS_VAND, "vand" },
	{ PPC_INS_VANDC, "vandc" },
	{ PPC_INS_VAVGSB, "vavgsb" },
	{ PPC_INS_VAVGSH, "vavgsh" },
	{ PPC_INS_VAVGSW, "vavgsw" },
	{ PPC_INS_VAVGUB, "vavgub" },
	{ PPC_INS_VAVGUH, "vavguh" },
	{ PPC_INS_VAVGUW, "vavguw" },
	{ PPC_INS_VCFSX, "vcfsx" },
	{ PPC_INS_VCFUX, "vcfux" },
	{ PPC_INS_VCMPBFP, "vcmpbfp" },
	{ PPC_INS_VCMPEQFP, "vcmpeqfp" },
	{ PPC_INS_VCMPEQUB, "vcmpequb" },
	{ PPC_INS_VCMPEQUH, "vcmpequh" },
	{ PPC_INS_VCMPEQUW, "vcmpequw" },
	{ PPC_INS_VCMPGEFP, "vcmpgefp" },
	{ PPC_INS_VCMPGTFP, "vcmpgtfp" },
	{ PPC_INS_VCMPGTSB, "vcmpgtsb" },
	{ PPC_INS_VCMPGTSH, "vcmpgtsh" },
	{ PPC_INS_VCMPGTSW, "vcmpgtsw" },
	{ PPC_INS_VCMPGTUB, "vcmpgtub" },
	{ PPC_INS_VCMPGTUH, "vcmpgtuh" },
	{ PPC_INS_VCMPGTUW, "vcmpgtuw" },
	{ PPC_INS_VCTSXS, "vctsxs" },
	{ PPC_INS_VCTUXS, "vctuxs" },
	{ PPC_INS_VEXPTEFP, "vexptefp" },
	{ PPC_INS_VLOGEFP, "vlogefp" },
	{ PPC_INS_VMADDFP, "vmaddfp" },
	{ PPC_INS_VMAXFP, "vmaxfp" },
	{ PPC_INS_VMAXSB, "vmaxsb" },
	{ PPC_INS_VMAXSH, "vmaxsh" },
	{ PPC_INS_VMAXSW, "vmaxsw" },
	{ PPC_INS_VMAXUB, "vmaxub" },
	{ PPC_INS_VMAXUH, "vmaxuh" },
	{ PPC_INS_VMAXUW, "vmaxuw" },
	{ PPC_INS_VMHADDSHS, "vmhaddshs" },
	{ PPC_INS_VMHRADDSHS, "vmhraddshs" },
	{ PPC_INS_VMINFP, "vminfp" },
	{ PPC_INS_VMINSB, "vminsb" },
	{ PPC_INS_VMINSH, "vminsh" },
	{ PPC_INS_VMINSW, "vminsw" },
	{ PPC_INS_VMINUB, "vminub" },
	{ PPC_INS_VMINUH, "vminuh" },
	{ PPC_INS_VMINUW, "vminuw" },
	{ PPC_INS_VMLADDUHM, "vmladduhm" },
	{ PPC_INS_VMRGHB, "vmrghb" },
	{ PPC_INS_VMRGHH, "vmrghh" },
	{ PPC_INS_VMRGHW, "vmrghw" },
	{ PPC_INS_VMRGLB, "vmrglb" },
	{ PPC_INS_VMRGLH, "vmrglh" },
	{ PPC_INS_VMRGLW, "vmrglw" },
	{ PPC_INS_VMSUMMBM, "vmsummbm" },
	{ PPC_INS_VMSUMSHM, "vmsumshm" },
	{ PPC_INS_VMSUMSHS, "vmsumshs" },
	{ PPC_INS_VMSUMUBM, "vmsumubm" },
	{ PPC_INS_VMSUMUHM, "vmsumuhm" },
	{ PPC_INS_VMSUMUHS, "vmsumuhs" },
	{ PPC_INS_VMULESB, "vmulesb" },
	{ PPC_INS_VMULESH, "vmulesh" },
	{ PPC_INS_VMULEUB, "vmuleub" },
	{ PPC_INS_VMULEUH, "vmuleuh" },
	{ PPC_INS_VMULOSB, "vmulosb" },
	{ PPC_INS_VMULOSH, "vmulosh" },
	{ PPC_INS_VMULOUB, "vmuloub" },
	{ PPC_INS_VMULOUH, "vmulouh" },
	{ PPC_INS_VNMSUBFP, "vnmsubfp" },
	{ PPC_INS_VNOR, "vnor" },
	{ PPC_INS_VOR, "vor" },
	{ PPC_INS_VPERM, "vperm" },
	{ PPC_INS_VPKPX, "vpkpx" },
	{ PPC_INS_VPKSHSS, "vpkshss" },
	{ PPC_INS_VPKSHUS, "vpkshus" },
	{ PPC_INS_VPKSWSS, "vpkswss" },
	{ PPC_INS_VPKSWUS, "vpkswus" },
	{ PPC_INS_VPKUHUM, "vpkuhum" },
	{ PPC_INS_VPKUHUS, "vpkuhus" },
	{ PPC_INS_VPKUWUM, "vpkuwum" },
	{ PPC_INS_VPKUWUS, "vpkuwus" },
	{ PPC_INS_VREFP, "vrefp" },
	{ PPC_INS_VRFIM, "vrfim" },
	{ PPC_INS_VRFIN, "vrfin" },
	{ PPC_INS_VRFIP, "vrfip" },
	{ PPC_INS_VRFIZ, "vrfiz" },
	{ PPC_INS_VRLB, "vrlb" },
	{ PPC_INS_VRLH, "vrlh" },
	{ PPC_INS_VRLW, "vrlw" },
	{ PPC_INS_VRSQRTEFP, "vrsqrtefp" },
	{ PPC_INS_VSEL, "vsel" },
	{ PPC_INS_VSL, "vsl" },
	{ PPC_INS_VSLB, "vslb" },
	{ PPC_INS_VSLDOI, "vsldoi" },
	{ PPC_INS_VSLH, "vslh" },
	{ PPC_INS_VSLO, "vslo" },
	{ PPC_INS_VSLW, "vslw" },
	{ PPC_INS_VSPLTB, "vspltb" },
	{ PPC_INS_VSPLTH, "vsplth" },
	{ PPC_INS_VSPLTISB, "vspltisb" },
	{ PPC_INS_VSPLTISH, "vspltish" },
	{ PPC_INS_VSPLTISW, "vspltisw" },
	{ PPC_INS_VSPLTW, "vspltw" },
	{ PPC_INS_VSR, "vsr" },
	{ PPC_INS_VSRAB, "vsrab" },
	{ PPC_INS_VSRAH, "vsrah" },
	{ PPC_INS_VSRAW, "vsraw" },
	{ PPC_INS_VSRB, "vsrb" },
	{ PPC_INS_VSRH, "vsrh" },
	{ PPC_INS_VSRO, "vsro" },
	{ PPC_INS_VSRW, "vsrw" },
	{ PPC_INS_VSUBCUW, "vsubcuw" },
	{ PPC_INS_VSUBFP, "vsubfp" },
	{ PPC_INS_VSUBSBS, "vsubsbs" },
	{ PPC_INS_VSUBSHS, "vsubshs" },
	{ PPC_INS_VSUBSWS, "vsubsws" },
	{ PPC_INS_VSUBUBM, "vsububm" },
	{ PPC_INS_VSUBUBS, "vsububs" },
	{ PPC_INS_VSUBUHM, "vsubuhm" },
	{ PPC_INS_VSUBUHS, "vsubuhs" },
	{ PPC_INS_VSUBUWM, "vsubuwm" },
	{ PPC_INS_VSUBUWS, "vsubuws" },
	{ PPC_INS_VSUM2SWS, "vsum2sws" },
	{ PPC_INS_VSUM4SBS, "vsum4sbs" },
	{ PPC_INS_VSUM4SHS, "vsum4shs" },
	{ PPC_INS_VSUM4UBS, "vsum4ubs" },
	{ PPC_INS_VSUMSWS, "vsumsws" },
	{ PPC_INS_VUPKHPX, "vupkhpx" },
	{ PPC_INS_VUPKHSB, "vupkhsb" },
	{ PPC_INS_VUPKHSH, "vupkhsh" },
	{ PPC_INS_VUPKLPX, "vupklpx" },
	{ PPC_INS_VUPKLSB, "vupklsb" },
	{ PPC_INS_VUPKLSH, "vupklsh" },
	{ PPC_INS_VXOR, "vxor" },
	{ PPC_INS_WAIT, "wait" },
	{ PPC_INS_WRTEE, "wrtee" },
	{ PPC_INS_WRTEEI, "wrteei" },
	{ PPC_INS_XOR, "xor" },
	{ PPC_INS_XORI, "xori" },
	{ PPC_INS_XORIS, "xoris" },
	{ PPC_INS_XSABSDP, "xsabsdp" },
	{ PPC_INS_XSADDDP, "xsadddp" },
	{ PPC_INS_XSCMPODP, "xscmpodp" },
	{ PPC_INS_XSCMPUDP, "xscmpudp" },
	{ PPC_INS_XSCPSGNDP, "xscpsgndp" },
	{ PPC_INS_XSCVDPSP, "xscvdpsp" },
	{ PPC_INS_XSCVDPSXDS, "xscvdpsxds" },
	{ PPC_INS_XSCVDPSXWS, "xscvdpsxws" },
	{ PPC_INS_XSCVDPUXDS, "xscvdpuxds" },
	{ PPC_INS_XSCVDPUXWS, "xscvdpuxws" },
	{ PPC_INS_XSCVSPDP, "xscvspdp" },
	{ PPC_INS_XSCVSXDDP, "xscvsxddp" },
	{ PPC_INS_XSCVUXDDP, "xscvuxddp" },
	{ PPC_INS_XSDIVDP, "xsdivdp" },
	{ PPC_INS_XSMADDADP, "xsmaddadp" },
	{ PPC_INS_XSMADDMDP, "xsmaddmdp" },
	{ PPC_INS_XSMAXDP, "xsmaxdp" },
	{ PPC_INS_XSMINDP, "xsmindp" },
	{ PPC_INS_XSMSUBADP, "xsmsubadp" },
	{ PPC_INS_XSMSUBMDP, "xsmsubmdp" },
	{ PPC_INS_XSMULDP, "xsmuldp" },
	{ PPC_INS_XSNABSDP, "xsnabsdp" },
	{ PPC_INS_XSNEGDP, "xsnegdp" },
	{ PPC_INS_XSNMADDADP, "xsnmaddadp" },
	{ PPC_INS_XSNMADDMDP, "xsnmaddmdp" },
	{ PPC_INS_XSNMSUBADP, "xsnmsubadp" },
	{ PPC_INS_XSNMSUBMDP, "xsnmsubmdp" },
	{ PPC_INS_XSRDPI, "xsrdpi" },
	{ PPC_INS_XSRDPIC, "xsrdpic" },
	{ PPC_INS_XSRDPIM, "xsrdpim" },
	{ PPC_INS_XSRDPIP, "xsrdpip" },
	{ PPC_INS_XSRDPIZ, "xsrdpiz" },
	{ PPC_INS_XSREDP, "xsredp" },
	{ PPC_INS_XSRSQRTEDP, "xsrsqrtedp" },
	{ PPC_INS_XSSQRTDP, "xssqrtdp" },
	{ PPC_INS_XSSUBDP, "xssubdp" },
	{ PPC_INS_XSTDIVDP, "xstdivdp" },
	{ PPC_INS_XSTSQRTDP, "xstsqrtdp" },
	{ PPC_INS_XVABSDP, "xvabsdp" },
	{ PPC_INS_XVABSSP, "xvabssp" },
	{ PPC_INS_XVADDDP, "xvadddp" },
	{ PPC_INS_XVADDSP, "xvaddsp" },
	{ PPC_INS_XVCMPEQDP, "xvcmpeqdp" },
	{ PPC_INS_XVCMPEQSP, "xvcmpeqsp" },
	{ PPC_INS_XVCMPGEDP, "xvcmpgedp" },
	{ PPC_INS_XVCMPGESP, "xvcmpgesp" },
	{ PPC_INS_XVCMPGTDP, "xvcmpgtdp" },
	{ PPC_INS_XVCMPGTSP, "xvcmpgtsp" },
	{ PPC_INS_XVCPSGNDP, "xvcpsgndp" },
	{ PPC_INS_XVCPSGNSP, "xvcpsgnsp" },
	{ PPC_INS_XVCVDPSP, "xvcvdpsp" },
	{ PPC_INS_XVCVDPSXDS, "xvcvdpsxds" },
	{ PPC_INS_XVCVDPSXWS, "xvcvdpsxws" },
	{ PPC_INS_XVCVDPUXDS, "xvcvdpuxds" },
	{ PPC_INS_XVCVDPUXWS, "xvcvdpuxws" },
	{ PPC_INS_XVCVSPDP, "xvcvspdp" },
	{ PPC_INS_XVCVSPSXDS, "xvcvspsxds" },
	{ PPC_INS_XVCVSPSXWS, "xvcvspsxws" },
	{ PPC_INS_XVCVSPUXDS, "xvcvspuxds" },
	{ PPC_INS_XVCVSPUXWS, "xvcvspuxws" },
	{ PPC_INS_XVCVSXDDP, "xvcvsxddp" },
	{ PPC_INS_XVCVSXDSP, "xvcvsxdsp" },
	{ PPC_INS_XVCVSXWDP, "xvcvsxwdp" },
	{ PPC_INS_XVCVSXWSP, "xvcvsxwsp" },
	{ PPC_INS_XVCVUXDDP, "xvcvuxddp" },
	{ PPC_INS_XVCVUXDSP, "xvcvuxdsp" },
	{ PPC_INS_XVCVUXWDP, "xvcvuxwdp" },
	{ PPC_INS_XVCVUXWSP, "xvcvuxwsp" },
	{ PPC_INS_XVDIVDP, "xvdivdp" },
	{ PPC_INS_XVDIVSP, "xvdivsp" },
	{ PPC_INS_XVMADDADP, "xvmaddadp" },
	{ PPC_INS_XVMADDASP, "xvmaddasp" },
	{ PPC_INS_XVMADDMDP, "xvmaddmdp" },
	{ PPC_INS_XVMADDMSP, "xvmaddmsp" },
	{ PPC_INS_XVMAXDP, "xvmaxdp" },
	{ PPC_INS_XVMAXSP, "xvmaxsp" },
	{ PPC_INS_XVMINDP, "xvmindp" },
	{ PPC_INS_XVMINSP, "xvminsp" },
	{ PPC_INS_XVMSUBADP, "xvmsubadp" },
	{ PPC_INS_XVMSUBASP, "xvmsubasp" },
	{ PPC_INS_XVMSUBMDP, "xvmsubmdp" },
	{ PPC_INS_XVMSUBMSP, "xvmsubmsp" },
	{ PPC_INS_XVMULDP, "xvmuldp" },
	{ PPC_INS_XVMULSP, "xvmulsp" },
	{ PPC_INS_XVNABSDP, "xvnabsdp" },
	{ PPC_INS_XVNABSSP, "xvnabssp" },
	{ PPC_INS_XVNEGDP, "xvnegdp" },
	{ PPC_INS_XVNEGSP, "xvnegsp" },
	{ PPC_INS_XVNMADDADP, "xvnmaddadp" },
	{ PPC_INS_XVNMADDASP, "xvnmaddasp" },
	{ PPC_INS_XVNMADDMDP, "xvnmaddmdp" },
	{ PPC_INS_XVNMADDMSP, "xvnmaddmsp" },
	{ PPC_INS_XVNMSUBADP, "xvnmsubadp" },
	{ PPC_INS_XVNMSUBASP, "xvnmsubasp" },
	{ PPC_INS_XVNMSUBMDP, "xvnmsubmdp" },
	{ PPC_INS_XVNMSUBMSP, "xvnmsubmsp" },
	{ PPC_INS_XVRDPI, "xvrdpi" },
	{ PPC_INS_XVRDPIC, "xvrdpic" },
	{ PPC_INS_XVRDPIM, "xvrdpim" },
	{ PPC_INS_XVRDPIP, "xvrdpip" },
	{ PPC_INS_XVRDPIZ, "xvrdpiz" },
	{ PPC_INS_XVREDP, "xvredp" },
	{ PPC_INS_XVRESP, "xvresp" },
	{ PPC_INS_XVRSPI, "xvrspi" },
	{ PPC_INS_XVRSPIC, "xvrspic" },
	{ PPC_INS_XVRSPIM, "xvrspim" },
	{ PPC_INS_XVRSPIP, "xvrspip" },
	{ PPC_INS_XVRSPIZ, "xvrspiz" },
	{ PPC_INS_XVRSQRTEDP, "xvrsqrtedp" },
	{ PPC_INS_XVRSQRTESP, "xvrsqrtesp" },
	{ PPC_INS_XVSQRTDP, "xvsqrtdp" },
	{ PPC_INS_XVSQRTSP, "xvsqrtsp" },
	{ PPC_INS_XVSUBDP, "xvsubdp" },
	{ PPC_INS_XVSUBSP, "xvsubsp" },
	{ PPC_INS_XVTDIVDP, "xvtdivdp" },
	{ PPC_INS_XVTDIVSP, "xvtdivsp" },
	{ PPC_INS_XVTSQRTDP, "xvtsqrtdp" },
	{ PPC_INS_XVTSQRTSP, "xvtsqrtsp" },
	{ PPC_INS_XXLAND, "xxland" },
	{ PPC_INS_XXLANDC, "xxlandc" },
	{ PPC_INS_XXLNOR, "xxlnor" },
	{ PPC_INS_XXLOR, "xxlor" },
	{ PPC_INS_XXLXOR, "xxlxor" },
	{ PPC_INS_XXMRGHW, "xxmrghw" },
	{ PPC_INS_XXMRGLW, "xxmrglw" },
	{ PPC_INS_XXPERMDI, "xxpermdi" },
	{ PPC_INS_XXSEL, "xxsel" },
	{ PPC_INS_XXSLDWI, "xxsldwi" },
	{ PPC_INS_XXSPLTW, "xxspltw" },
	{ PPC_INS_BCA, "bca" },
	{ PPC_INS_BCLA, "bcla" },

	// extra & alias instructions
	{ PPC_INS_SLWI, "slwi" },
	{ PPC_INS_SRWI, "srwi" },
	{ PPC_INS_SLDI, "sldi" },
	{ PPC_INS_BTA, "bta" },
	{ PPC_INS_CRSET, "crset" },
	{ PPC_INS_CRNOT, "crnot" },
	{ PPC_INS_CRMOVE, "crmove" },
	{ PPC_INS_CRCLR, "crclr" },
	{ PPC_INS_MFBR0, "mfbr0" },
	{ PPC_INS_MFBR1, "mfbr1" },
	{ PPC_INS_MFBR2, "mfbr2" },
	{ PPC_INS_MFBR3, "mfbr3" },
	{ PPC_INS_MFBR4, "mfbr4" },
	{ PPC_INS_MFBR5, "mfbr5" },
	{ PPC_INS_MFBR6, "mfbr6" },
	{ PPC_INS_MFBR7, "mfbr7" },
	{ PPC_INS_MFXER, "mfxer" },
	{ PPC_INS_MFRTCU, "mfrtcu" },
	{ PPC_INS_MFRTCL, "mfrtcl" },
	{ PPC_INS_MFDSCR, "mfdscr" },
	{ PPC_INS_MFDSISR, "mfdsisr" },
	{ PPC_INS_MFDAR, "mfdar" },
	{ PPC_INS_MFSRR2, "mfsrr2" },
	{ PPC_INS_MFSRR3, "mfsrr3" },
	{ PPC_INS_MFCFAR, "mfcfar" },
	{ PPC_INS_MFAMR, "mfamr" },
	{ PPC_INS_MFPID, "mfpid" },
	{ PPC_INS_MFTBLO, "mftblo" },
	{ PPC_INS_MFTBHI, "mftbhi" },
	{ PPC_INS_MFDBATU, "mfdbatu" },
	{ PPC_INS_MFDBATL, "mfdbatl" },
	{ PPC_INS_MFIBATU, "mfibatu" },
	{ PPC_INS_MFIBATL, "mfibatl" },
	{ PPC_INS_MFDCCR, "mfdccr" },
	{ PPC_INS_MFICCR, "mficcr" },
	{ PPC_INS_MFDEAR, "mfdear" },
	{ PPC_INS_MFESR, "mfesr" },
	{ PPC_INS_MFSPEFSCR, "mfspefscr" },
	{ PPC_INS_MFTCR, "mftcr" },
	{ PPC_INS_MFASR, "mfasr" },
	{ PPC_INS_MFPVR, "mfpvr" },
	{ PPC_INS_MFTBU, "mftbu" },
	{ PPC_INS_MTCR, "mtcr" },
	{ PPC_INS_MTBR0, "mtbr0" },
	{ PPC_INS_MTBR1, "mtbr1" },
	{ PPC_INS_MTBR2, "mtbr2" },
	{ PPC_INS_MTBR3, "mtbr3" },
	{ PPC_INS_MTBR4, "mtbr4" },
	{ PPC_INS_MTBR5, "mtbr5" },
	{ PPC_INS_MTBR6, "mtbr6" },
	{ PPC_INS_MTBR7, "mtbr7" },
	{ PPC_INS_MTXER, "mtxer" },
	{ PPC_INS_MTDSCR, "mtdscr" },
	{ PPC_INS_MTDSISR, "mtdsisr" },
	{ PPC_INS_MTDAR, "mtdar" },
	{ PPC_INS_MTSRR2, "mtsrr2" },
	{ PPC_INS_MTSRR3, "mtsrr3" },
	{ PPC_INS_MTCFAR, "mtcfar" },
	{ PPC_INS_MTAMR, "mtamr" },
	{ PPC_INS_MTPID, "mtpid" },
	{ PPC_INS_MTTBL, "mttbl" },
	{ PPC_INS_MTTBU, "mttbu" },
	{ PPC_INS_MTTBLO, "mttblo" },
	{ PPC_INS_MTTBHI, "mttbhi" },
	{ PPC_INS_MTDBATU, "mtdbatu" },
	{ PPC_INS_MTDBATL, "mtdbatl" },
	{ PPC_INS_MTIBATU, "mtibatu" },
	{ PPC_INS_MTIBATL, "mtibatl" },
	{ PPC_INS_MTDCCR, "mtdccr" },
	{ PPC_INS_MTICCR, "mticcr" },
	{ PPC_INS_MTDEAR, "mtdear" },
	{ PPC_INS_MTESR, "mtesr" },
	{ PPC_INS_MTSPEFSCR, "mtspefscr" },
	{ PPC_INS_MTTCR, "mttcr" },
	{ PPC_INS_NOT, "not" },
	{ PPC_INS_MR, "mr" },
	{ PPC_INS_ROTLD, "rotld" },
	{ PPC_INS_ROTLDI, "rotldi" },
	{ PPC_INS_CLRLDI, "clrldi" },
	{ PPC_INS_ROTLWI, "rotlwi" },
	{ PPC_INS_CLRLWI, "clrlwi" },
	{ PPC_INS_ROTLW, "rotlw" },
	{ PPC_INS_SUB, "sub" },
	{ PPC_INS_SUBC, "subc" },
	{ PPC_INS_LWSYNC, "lwsync" },
	{ PPC_INS_PTESYNC, "ptesync" },
	{ PPC_INS_TDLT, "tdlt" },
	{ PPC_INS_TDEQ, "tdeq" },
	{ PPC_INS_TDGT, "tdgt" },
	{ PPC_INS_TDNE, "tdne" },
	{ PPC_INS_TDLLT, "tdllt" },
	{ PPC_INS_TDLGT, "tdlgt" },
	{ PPC_INS_TDU, "tdu" },
	{ PPC_INS_TDLTI, "tdlti" },
	{ PPC_INS_TDEQI, "tdeqi" },
	{ PPC_INS_TDGTI, "tdgti" },
	{ PPC_INS_TDNEI, "tdnei" },
	{ PPC_INS_TDLLTI, "tdllti" },
	{ PPC_INS_TDLGTI, "tdlgti" },
	{ PPC_INS_TDUI, "tdui" },
	{ PPC_INS_TLBREHI, "tlbrehi" },
	{ PPC_INS_TLBRELO, "tlbrelo" },
	{ PPC_INS_TLBWEHI, "tlbwehi" },
	{ PPC_INS_TLBWELO, "tlbwelo" },
	{ PPC_INS_TWLT, "twlt" },
	{ PPC_INS_TWEQ, "tweq" },
	{ PPC_INS_TWGT, "twgt" },
	{ PPC_INS_TWNE, "twne" },
	{ PPC_INS_TWLLT, "twllt" },
	{ PPC_INS_TWLGT, "twlgt" },
	{ PPC_INS_TWU, "twu" },
	{ PPC_INS_TWLTI, "twlti" },
	{ PPC_INS_TWEQI, "tweqi" },
	{ PPC_INS_TWGTI, "twgti" },
	{ PPC_INS_TWNEI, "twnei" },
	{ PPC_INS_TWLLTI, "twllti" },
	{ PPC_INS_TWLGTI, "twlgti" },
	{ PPC_INS_TWUI, "twui" },
	{ PPC_INS_WAITRSV, "waitrsv" },
	{ PPC_INS_WAITIMPL, "waitimpl" },
	{ PPC_INS_XNOP, "xnop" },
	{ PPC_INS_XVMOVDP, "xvmovdp" },
	{ PPC_INS_XVMOVSP, "xvmovsp" },
	{ PPC_INS_XXSPLTD, "xxspltd" },
	{ PPC_INS_XXMRGHD, "xxmrghd" },
	{ PPC_INS_XXMRGLD, "xxmrgld" },
	{ PPC_INS_XXSWAPD, "xxswapd" },
	{ PPC_INS_BT, "bt" },
	{ PPC_INS_BF, "bf" },
	{ PPC_INS_BDNZT, "bdnzt" },
	{ PPC_INS_BDNZF, "bdnzf" },
	{ PPC_INS_BDZF, "bdzf" },
	{ PPC_INS_BDZT, "bdzt" },
	{ PPC_INS_BFA, "bfa" },
	{ PPC_INS_BDNZTA, "bdnzta" },
	{ PPC_INS_BDNZFA, "bdnzfa" },
	{ PPC_INS_BDZTA, "bdzta" },
	{ PPC_INS_BDZFA, "bdzfa" },
	{ PPC_INS_BTCTR, "btctr" },
	{ PPC_INS_BFCTR, "bfctr" },
	{ PPC_INS_BTCTRL, "btctrl" },
	{ PPC_INS_BFCTRL, "bfctrl" },
	{ PPC_INS_BTL, "btl" },
	{ PPC_INS_BFL, "bfl" },
	{ PPC_INS_BDNZTL, "bdnztl" },
	{ PPC_INS_BDNZFL, "bdnzfl" },
	{ PPC_INS_BDZTL, "bdztl" },
	{ PPC_INS_BDZFL, "bdzfl" },
	{ PPC_INS_BTLA, "btla" },
	{ PPC_INS_BFLA, "bfla" },
	{ PPC_INS_BDNZTLA, "bdnztla" },
	{ PPC_INS_BDNZFLA, "bdnzfla" },
	{ PPC_INS_BDZTLA, "bdztla" },
	{ PPC_INS_BDZFLA, "bdzfla" },
	{ PPC_INS_BTLR, "btlr" },
	{ PPC_INS_BFLR, "bflr" },
	{ PPC_INS_BDNZTLR, "bdnztlr" },
	{ PPC_INS_BDZTLR, "bdztlr" },
	{ PPC_INS_BDZFLR, "bdzflr" },
	{ PPC_INS_BTLRL, "btlrl" },
	{ PPC_INS_BFLRL, "bflrl" },
	{ PPC_INS_BDNZTLRL, "bdnztlrl" },
	{ PPC_INS_BDNZFLRL, "bdnzflrl" },
	{ PPC_INS_BDZTLRL, "bdztlrl" },
	{ PPC_INS_BDZFLRL, "bdzflrl" },
};

// special alias insn
static const name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *PPC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= PPC_INS_ENDING)
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
	{ PPC_GRP_INVALID, NULL },
	{ PPC_GRP_JUMP,	"jump" },

	// architecture-specific groups
	{ PPC_GRP_ALTIVEC, "altivec" },
	{ PPC_GRP_MODE32, "mode32" },
	{ PPC_GRP_MODE64, "mode64" },
	{ PPC_GRP_BOOKE, "booke" },
	{ PPC_GRP_NOTBOOKE, "notbooke" },
	{ PPC_GRP_SPE, "spe" },
	{ PPC_GRP_VSX, "vsx" },
	{ PPC_GRP_E500, "e500" },
	{ PPC_GRP_PPC4XX, "ppc4xx" },
	{ PPC_GRP_PPC6XX, "ppc6xx" },
};
#endif

const char *PPC_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= PPC_GRP_ENDING || (id > PPC_GRP_JUMP && id < PPC_GRP_ALTIVEC))
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
ppc_reg PPC_map_register(unsigned int r)
{
	static const unsigned int map[] = { 0,
		0, PPC_REG_CARRY, PPC_REG_CC, PPC_REG_CTR, 0,
		PPC_REG_LR, 0, PPC_REG_VRSAVE, PPC_REG_R0, 0,
		PPC_REG_CR0, PPC_REG_CR1, PPC_REG_CR2, PPC_REG_CR3, PPC_REG_CR4,
		PPC_REG_CR5, PPC_REG_CR6, PPC_REG_CR7, PPC_REG_CTR, PPC_REG_F0,
		PPC_REG_F1, PPC_REG_F2, PPC_REG_F3, PPC_REG_F4, PPC_REG_F5,
		PPC_REG_F6, PPC_REG_F7, PPC_REG_F8, PPC_REG_F9, PPC_REG_F10,
		PPC_REG_F11, PPC_REG_F12, PPC_REG_F13, PPC_REG_F14, PPC_REG_F15,
		PPC_REG_F16, PPC_REG_F17, PPC_REG_F18, PPC_REG_F19, PPC_REG_F20,
		PPC_REG_F21, PPC_REG_F22, PPC_REG_F23, PPC_REG_F24, PPC_REG_F25,
		PPC_REG_F26, PPC_REG_F27, PPC_REG_F28, PPC_REG_F29, PPC_REG_F30,
		PPC_REG_F31, 0, PPC_REG_LR, PPC_REG_R0, PPC_REG_R1,
		PPC_REG_R2, PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
		PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10, PPC_REG_R11,
		PPC_REG_R12, PPC_REG_R13, PPC_REG_R14, PPC_REG_R15, PPC_REG_R16,
		PPC_REG_R17, PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21,
		PPC_REG_R22, PPC_REG_R23, PPC_REG_R24, PPC_REG_R25, PPC_REG_R26,
		PPC_REG_R27, PPC_REG_R28, PPC_REG_R29, PPC_REG_R30, PPC_REG_R31,
		PPC_REG_V0, PPC_REG_V1, PPC_REG_V2, PPC_REG_V3, PPC_REG_V4,
		PPC_REG_V5, PPC_REG_V6, PPC_REG_V7, PPC_REG_V8, PPC_REG_V9,
		PPC_REG_V10, PPC_REG_V11, PPC_REG_V12, PPC_REG_V13, PPC_REG_V14,
		PPC_REG_V15, PPC_REG_V16, PPC_REG_V17, PPC_REG_V18, PPC_REG_V19,
		PPC_REG_V20, PPC_REG_V21, PPC_REG_V22, PPC_REG_V23, PPC_REG_V24,
		PPC_REG_V25, PPC_REG_V26, PPC_REG_V27, PPC_REG_V28, PPC_REG_V29,
		PPC_REG_V30, PPC_REG_V31, PPC_REG_VS32, PPC_REG_VS33, PPC_REG_VS34,
		PPC_REG_VS35, PPC_REG_VS36, PPC_REG_VS37, PPC_REG_VS38, PPC_REG_VS39,
		PPC_REG_VS40, PPC_REG_VS41, PPC_REG_VS42, PPC_REG_VS43, PPC_REG_VS44,
		PPC_REG_VS45, PPC_REG_VS46, PPC_REG_VS47, PPC_REG_VS48, PPC_REG_VS49,
		PPC_REG_VS50, PPC_REG_VS51, PPC_REG_VS52, PPC_REG_VS53, PPC_REG_VS54,
		PPC_REG_VS55, PPC_REG_VS56, PPC_REG_VS57, PPC_REG_VS58, PPC_REG_VS59,
		PPC_REG_VS60, PPC_REG_VS61, PPC_REG_VS62, PPC_REG_VS63, PPC_REG_VS32,
		PPC_REG_VS33, PPC_REG_VS34, PPC_REG_VS35, PPC_REG_VS36, PPC_REG_VS37,
		PPC_REG_VS38, PPC_REG_VS39, PPC_REG_VS40, PPC_REG_VS41, PPC_REG_VS42,
		PPC_REG_VS43, PPC_REG_VS44, PPC_REG_VS45, PPC_REG_VS46, PPC_REG_VS47,
		PPC_REG_VS48, PPC_REG_VS49, PPC_REG_VS50, PPC_REG_VS51, PPC_REG_VS52,
		PPC_REG_VS53, PPC_REG_VS54, PPC_REG_VS55, PPC_REG_VS56, PPC_REG_VS57,
		PPC_REG_VS58, PPC_REG_VS59, PPC_REG_VS60, PPC_REG_VS61, PPC_REG_VS62,
		PPC_REG_VS63, PPC_REG_VS0, PPC_REG_VS1, PPC_REG_VS2, PPC_REG_VS3,
		PPC_REG_VS4, PPC_REG_VS5, PPC_REG_VS6, PPC_REG_VS7, PPC_REG_VS8,
		PPC_REG_VS9, PPC_REG_VS10, PPC_REG_VS11, PPC_REG_VS12, PPC_REG_VS13,
		PPC_REG_VS14, PPC_REG_VS15, PPC_REG_VS16, PPC_REG_VS17, PPC_REG_VS18,
		PPC_REG_VS19, PPC_REG_VS20, PPC_REG_VS21, PPC_REG_VS22, PPC_REG_VS23,
		PPC_REG_VS24, PPC_REG_VS25, PPC_REG_VS26, PPC_REG_VS27, PPC_REG_VS28,
		PPC_REG_VS29, PPC_REG_VS30, PPC_REG_VS31, PPC_REG_R0, PPC_REG_R1,
		PPC_REG_R2, PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
		PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10, PPC_REG_R11,
		PPC_REG_R12, PPC_REG_R13, PPC_REG_R14, PPC_REG_R15, PPC_REG_R16,
		PPC_REG_R17, PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21,
		PPC_REG_R22, PPC_REG_R23, PPC_REG_R24, PPC_REG_R25, PPC_REG_R26,
		PPC_REG_R27, PPC_REG_R28, PPC_REG_R29, PPC_REG_R30, PPC_REG_R31,
		PPC_REG_R0, PPC_REG_R2, PPC_REG_R6, PPC_REG_R10, PPC_REG_R14,
		PPC_REG_R18, PPC_REG_R22, PPC_REG_R26, PPC_REG_R30, PPC_REG_R1,
		PPC_REG_R5, PPC_REG_R9, PPC_REG_R13, PPC_REG_R17, PPC_REG_R21,
		PPC_REG_R25, PPC_REG_R29, PPC_REG_R0, PPC_REG_R4, PPC_REG_R8,
		PPC_REG_R12, PPC_REG_R16, PPC_REG_R20, PPC_REG_R24, PPC_REG_R28,
		PPC_REG_R3, PPC_REG_R7, PPC_REG_R11, PPC_REG_R15, PPC_REG_R19,
		PPC_REG_R23, PPC_REG_R27, PPC_REG_R31, };

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

static const struct ppc_alias alias_insn_name_maps[] = {
	//{ PPC_INS_BTA, "bta" },
	{ PPC_INS_B, PPC_BC_LT, "blt" },
	{ PPC_INS_B, PPC_BC_LE, "ble" },
	{ PPC_INS_B, PPC_BC_EQ, "beq" },
	{ PPC_INS_B, PPC_BC_GE, "bge" },
	{ PPC_INS_B, PPC_BC_GT, "bgt" },
	{ PPC_INS_B, PPC_BC_NE, "bne" },
	{ PPC_INS_B, PPC_BC_UN, "bun" },
	{ PPC_INS_B, PPC_BC_NU, "bnu" },
	{ PPC_INS_B, PPC_BC_SO, "bso" },
	{ PPC_INS_B, PPC_BC_NS, "bns" },

	{ PPC_INS_BA, PPC_BC_LT, "blta" },
	{ PPC_INS_BA, PPC_BC_LE, "blea" },
	{ PPC_INS_BA, PPC_BC_EQ, "beqa" },
	{ PPC_INS_BA, PPC_BC_GE, "bgea" },
	{ PPC_INS_BA, PPC_BC_GT, "bgta" },
	{ PPC_INS_BA, PPC_BC_NE, "bnea" },
	{ PPC_INS_BA, PPC_BC_UN, "buna" },
	{ PPC_INS_BA, PPC_BC_NU, "bnua" },
	{ PPC_INS_BA, PPC_BC_SO, "bsoa" },
	{ PPC_INS_BA, PPC_BC_NS, "bnsa" },

	{ PPC_INS_BCTR, PPC_BC_LT, "bltctr" },
	{ PPC_INS_BCTR, PPC_BC_LE, "blectr" },
	{ PPC_INS_BCTR, PPC_BC_EQ, "beqctr" },
	{ PPC_INS_BCTR, PPC_BC_GE, "bgectr" },
	{ PPC_INS_BCTR, PPC_BC_GT, "bgtctr" },
	{ PPC_INS_BCTR, PPC_BC_NE, "bnectr" },
	{ PPC_INS_BCTR, PPC_BC_UN, "bunctr" },
	{ PPC_INS_BCTR, PPC_BC_NU, "bnuctr" },
	{ PPC_INS_BCTR, PPC_BC_SO, "bsoctr" },
	{ PPC_INS_BCTR, PPC_BC_NS, "bnsctr" },

	{ PPC_INS_BCTRL, PPC_BC_LT, "bltctrl" },
	{ PPC_INS_BCTRL, PPC_BC_LE, "blectrl" },
	{ PPC_INS_BCTRL, PPC_BC_EQ, "beqctrl" },
	{ PPC_INS_BCTRL, PPC_BC_GE, "bgectrl" },
	{ PPC_INS_BCTRL, PPC_BC_GT, "bgtctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NE, "bnectrl" },
	{ PPC_INS_BCTRL, PPC_BC_UN, "bunctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NU, "bnuctrl" },
	{ PPC_INS_BCTRL, PPC_BC_SO, "bsoctrl" },
	{ PPC_INS_BCTRL, PPC_BC_NS, "bnsctrl" },

	{ PPC_INS_BL, PPC_BC_LT, "bltl" },
	{ PPC_INS_BL, PPC_BC_LE, "blel" },
	{ PPC_INS_BL, PPC_BC_EQ, "beql" },
	{ PPC_INS_BL, PPC_BC_GE, "bgel" },
	{ PPC_INS_BL, PPC_BC_GT, "bgtl" },
	{ PPC_INS_BL, PPC_BC_NE, "bnel" },
	{ PPC_INS_BL, PPC_BC_UN, "bunl" },
	{ PPC_INS_BL, PPC_BC_NU, "bnul" },
	{ PPC_INS_BL, PPC_BC_SO, "bsol" },
	{ PPC_INS_BL, PPC_BC_NS, "bnsl" },

	{ PPC_INS_BLA, PPC_BC_LT, "bltla" },
	{ PPC_INS_BLA, PPC_BC_LE, "blela" },
	{ PPC_INS_BLA, PPC_BC_EQ, "beqla" },
	{ PPC_INS_BLA, PPC_BC_GE, "bgela" },
	{ PPC_INS_BLA, PPC_BC_GT, "bgtla" },
	{ PPC_INS_BLA, PPC_BC_NE, "bnela" },
	{ PPC_INS_BLA, PPC_BC_UN, "bunla" },
	{ PPC_INS_BLA, PPC_BC_NU, "bnula" },
	{ PPC_INS_BLA, PPC_BC_SO, "bsola" },
	{ PPC_INS_BLA, PPC_BC_NS, "bnsla" },

	{ PPC_INS_BLR, PPC_BC_LT, "bltlr" },
	{ PPC_INS_BLR, PPC_BC_LE, "blelr" },
	{ PPC_INS_BLR, PPC_BC_EQ, "beqlr" },
	{ PPC_INS_BLR, PPC_BC_GE, "bgelr" },
	{ PPC_INS_BLR, PPC_BC_GT, "bgtlr" },
	{ PPC_INS_BLR, PPC_BC_NE, "bnelr" },
	{ PPC_INS_BLR, PPC_BC_UN, "bunlr" },
	{ PPC_INS_BLR, PPC_BC_NU, "bnulr" },
	{ PPC_INS_BLR, PPC_BC_SO, "bsolr" },
	{ PPC_INS_BLR, PPC_BC_NS, "bnslr" },

	{ PPC_INS_BLRL, PPC_BC_LT, "bltlrl" },
	{ PPC_INS_BLRL, PPC_BC_LE, "blelrl" },
	{ PPC_INS_BLRL, PPC_BC_EQ, "beqlrl" },
	{ PPC_INS_BLRL, PPC_BC_GE, "bgelrl" },
	{ PPC_INS_BLRL, PPC_BC_GT, "bgtlrl" },
	{ PPC_INS_BLRL, PPC_BC_NE, "bnelrl" },
	{ PPC_INS_BLRL, PPC_BC_UN, "bunlrl" },
	{ PPC_INS_BLRL, PPC_BC_NU, "bnulrl" },
	{ PPC_INS_BLRL, PPC_BC_SO, "bsolrl" },
	{ PPC_INS_BLRL, PPC_BC_NS, "bnslrl" },
};

// given alias mnemonic, return instruction ID & CC
bool PPC_alias_insn(const char *name, struct ppc_alias *alias)
{
	size_t i;
#ifndef CAPSTONE_DIET
	int x;
#endif

	for(i = 0; i < ARR_SIZE(alias_insn_name_maps); i++) {
		if (!strcmp(name, alias_insn_name_maps[i].mnem)) {
			alias->id = alias_insn_name_maps[i].id;
			alias->cc = alias_insn_name_maps[i].cc;
			return true;
		}
	}

#ifndef CAPSTONE_DIET
	// not really an alias insn
	x = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);
	if (x != -1) {
		alias->id = insn_name_maps[x].id;
		alias->cc = PPC_BC_INVALID;
		return true;
	}
#endif

	// not found
	return false;
}

// list all relative branch instructions
static const unsigned int insn_abs[] = {
	PPC_BA,
	PPC_BCCA,
	PPC_BCCLA,
	PPC_BDNZA,
	PPC_BDNZAm,
	PPC_BDNZAp,
	PPC_BDNZLA,
	PPC_BDNZLAm,
	PPC_BDNZLAp,
	PPC_BDZA,
	PPC_BDZAm,
	PPC_BDZAp,
	PPC_BDZLAm,
	PPC_BDZLAp,
	PPC_BLA,
	PPC_gBCA,
	PPC_gBCLA,
	0
};

// check if this insn is relative branch
bool PPC_abs_branch(cs_struct *h, unsigned int id)
{
	int i;

	for (i = 0; insn_abs[i]; i++) {
		if (id == insn_abs[i]) {
			return true;
		}
	}

	// not found
	return false;
}

#endif
