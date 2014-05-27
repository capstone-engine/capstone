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
static name_map reg_name_maps[] = {
	{ PPC_REG_INVALID, NULL },

	{ PPC_REG_CARRY, "ca" },
	{ PPC_REG_CR0, "cr0" },
	{ PPC_REG_CR1, "cr1" },
	{ PPC_REG_CR2, "cr2" },
	{ PPC_REG_CR3, "cr3" },
	{ PPC_REG_CR4, "cr4" },
	{ PPC_REG_CR5, "cr5" },
	{ PPC_REG_CR6, "cr6" },
	{ PPC_REG_CR7, "cr7" },
	{ PPC_REG_CR8, "cr8" },
	{ PPC_REG_CR9, "cr9" },
	{ PPC_REG_CR10, "cr10" },
	{ PPC_REG_CR11, "cr11" },
	{ PPC_REG_CR12, "cr12" },
	{ PPC_REG_CR13, "cr13" },
	{ PPC_REG_CR14, "cr14" },
	{ PPC_REG_CR15, "cr15" },
	{ PPC_REG_CR16, "cr16" },
	{ PPC_REG_CR17, "cr17" },
	{ PPC_REG_CR18, "cr18" },
	{ PPC_REG_CR19, "cr19" },
	{ PPC_REG_CR20, "cr20" },
	{ PPC_REG_CR21, "cr21" },
	{ PPC_REG_CR22, "cr22" },
	{ PPC_REG_CR23, "cr23" },
	{ PPC_REG_CR24, "cr24" },
	{ PPC_REG_CR25, "cr25" },
	{ PPC_REG_CR26, "cr26" },
	{ PPC_REG_CR27, "cr27" },
	{ PPC_REG_CR28, "cr28" },
	{ PPC_REG_CR29, "cr29" },
	{ PPC_REG_CR30, "cr30" },
	{ PPC_REG_CR31, "cr31" },
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
	if (reg >= PPC_REG_MAX)
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
		PPC_BCC, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCCA, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCCL, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCLA, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTR, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		PPC_BCCTR8, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, 0 }, { 0 }, { PPC_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		PPC_BCCTRL, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCCTRL8, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_CTR8, PPC_REG_RM, 0 }, { PPC_REG_LR8, 0 }, { PPC_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		PPC_BCLR, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		PPC_BCLRL, PPC_INS_B,
#ifndef CAPSTONE_DIET
		{ PPC_REG_LR, PPC_REG_RM, 0 }, { PPC_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		PPC_BCLalways, PPC_INS_BCL,
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
		PPC_LDtoc_restore, PPC_INS_LD,
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
		PPC_TLBSYNC, PPC_INS_TLBSYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
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
static name_map insn_name_maps[] = {
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
	{ PPC_INS_BCL, "bcl" },
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
	{ PPC_INS_MCRF, "mcrf" },
	{ PPC_INS_MFCR, "mfcr" },
	{ PPC_INS_MFCTR, "mfctr" },
	{ PPC_INS_MFFS, "mffs" },
	{ PPC_INS_MFLR, "mflr" },
	{ PPC_INS_MFMSR, "mfmsr" },
	{ PPC_INS_MFOCRF, "mfocrf" },
	{ PPC_INS_MFSPR, "mfspr" },
	{ PPC_INS_MFTB, "mftb" },
	{ PPC_INS_MFVSCR, "mfvscr" },
	{ PPC_INS_MSYNC, "msync" },
	{ PPC_INS_MTCRF, "mtcrf" },
	{ PPC_INS_MTCTR, "mtctr" },
	{ PPC_INS_MTFSB0, "mtfsb0" },
	{ PPC_INS_MTFSB1, "mtfsb1" },
	{ PPC_INS_MTFSF, "mtfsf" },
	{ PPC_INS_MTLR, "mtlr" },
	{ PPC_INS_MTMSR, "mtmsr" },
	{ PPC_INS_MTMSRD, "mtmsrd" },
	{ PPC_INS_MTOCRF, "mtocrf" },
	{ PPC_INS_MTSPR, "mtspr" },
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
	{ PPC_INS_SUBF, "subf" },
	{ PPC_INS_SUBFC, "subfc" },
	{ PPC_INS_SUBFE, "subfe" },
	{ PPC_INS_SUBFIC, "subfic" },
	{ PPC_INS_SUBFME, "subfme" },
	{ PPC_INS_SUBFZE, "subfze" },
	{ PPC_INS_SYNC, "sync" },
	{ PPC_INS_TD, "td" },
	{ PPC_INS_TDI, "tdi" },
	{ PPC_INS_TLBIE, "tlbie" },
	{ PPC_INS_TLBIEL, "tlbiel" },
	{ PPC_INS_TLBSYNC, "tlbsync" },
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
	{ PPC_INS_XOR, "xor" },
	{ PPC_INS_XORI, "xori" },
	{ PPC_INS_XORIS, "xoris" },
	{ PPC_INS_BC, "bc" },
	{ PPC_INS_BCA, "bca" },
	{ PPC_INS_BCCTR, "bcctr" },
	{ PPC_INS_BCCTRL, "bcctrl" },
	{ PPC_INS_BCLA, "bcla" },
	{ PPC_INS_BCLR, "bclr" },
	{ PPC_INS_BCLRL, "bclrl" },
};

// special alias insn
static name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *PPC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= PPC_INS_MAX)
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
ppc_reg PPC_map_register(unsigned int r)
{
	static unsigned int map[] = {
		0, 0, PPC_REG_CARRY, PPC_REG_CTR, 0, PPC_REG_LR,
		0, PPC_REG_VRSAVE, PPC_REG_CR0, 0, PPC_REG_CR0,
		PPC_REG_CR1, PPC_REG_CR2, PPC_REG_CR3, PPC_REG_CR4, PPC_REG_CR5,
		PPC_REG_CR6, PPC_REG_CR7, PPC_REG_CTR, PPC_REG_F0, PPC_REG_F1,
		PPC_REG_F2, PPC_REG_F3, PPC_REG_F4, PPC_REG_F5, PPC_REG_F6,
		PPC_REG_F7, PPC_REG_F8, PPC_REG_F9, PPC_REG_F10, PPC_REG_F11,
		PPC_REG_F12, PPC_REG_F13, PPC_REG_F14, PPC_REG_F15, PPC_REG_F16,
		PPC_REG_F17, PPC_REG_F18, PPC_REG_F19, PPC_REG_F20, PPC_REG_F21,
		PPC_REG_F22, PPC_REG_F23, PPC_REG_F24, PPC_REG_F25, PPC_REG_F26,
		PPC_REG_F27, PPC_REG_F28, PPC_REG_F29, PPC_REG_F30, PPC_REG_F31,
		0, PPC_REG_LR, PPC_REG_R0, PPC_REG_R1, PPC_REG_R2,
		PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6, PPC_REG_R7,
		PPC_REG_R8, PPC_REG_R9, PPC_REG_R10, PPC_REG_R11, PPC_REG_R12,
		PPC_REG_R13, PPC_REG_R14, PPC_REG_R15, PPC_REG_R16, PPC_REG_R17,
		PPC_REG_R18, PPC_REG_R19, PPC_REG_R20, PPC_REG_R21, PPC_REG_R22,
		PPC_REG_R23, PPC_REG_R24, PPC_REG_R25, PPC_REG_R26, PPC_REG_R27,
		PPC_REG_R28, PPC_REG_R29, PPC_REG_R30, PPC_REG_R31, PPC_REG_V0,
		PPC_REG_V1, PPC_REG_V2, PPC_REG_V3, PPC_REG_V4, PPC_REG_V5,
		PPC_REG_V6, PPC_REG_V7, PPC_REG_V8, PPC_REG_V9, PPC_REG_V10,
		PPC_REG_V11, PPC_REG_V12, PPC_REG_V13, PPC_REG_V14, PPC_REG_V15,
		PPC_REG_V16, PPC_REG_V17, PPC_REG_V18, PPC_REG_V19, PPC_REG_V20,
		PPC_REG_V21, PPC_REG_V22, PPC_REG_V23, PPC_REG_V24, PPC_REG_V25,
		PPC_REG_V26, PPC_REG_V27, PPC_REG_V28, PPC_REG_V29, PPC_REG_V30,
		PPC_REG_V31, PPC_REG_R0, PPC_REG_R1, PPC_REG_R2, PPC_REG_R3,
		PPC_REG_R4, PPC_REG_R5, PPC_REG_R6, PPC_REG_R7, PPC_REG_R8,
		PPC_REG_R9, PPC_REG_R10, PPC_REG_R11, PPC_REG_R12, PPC_REG_R13,
		PPC_REG_R14, PPC_REG_R15, PPC_REG_R16, PPC_REG_R17, PPC_REG_R18,
		PPC_REG_R19, PPC_REG_R20, PPC_REG_R21, PPC_REG_R22, PPC_REG_R23,
		PPC_REG_R24, PPC_REG_R25, PPC_REG_R26, PPC_REG_R27, PPC_REG_R28,
		PPC_REG_R29, PPC_REG_R30, PPC_REG_R31, PPC_REG_CR0, PPC_REG_CR2,
		PPC_REG_CR6, PPC_REG_CR10, PPC_REG_CR14, PPC_REG_CR18, PPC_REG_CR22,
		PPC_REG_CR26, PPC_REG_CR30, PPC_REG_CR1, PPC_REG_CR5, PPC_REG_CR9,
		PPC_REG_CR13, PPC_REG_CR17, PPC_REG_CR21, PPC_REG_CR25, PPC_REG_CR29,
		PPC_REG_CR0, PPC_REG_CR4, PPC_REG_CR8, PPC_REG_CR12, PPC_REG_CR16,
		PPC_REG_CR20, PPC_REG_CR24, PPC_REG_CR28, PPC_REG_CR3, PPC_REG_CR7,
		PPC_REG_CR11, PPC_REG_CR15, PPC_REG_CR19, PPC_REG_CR23, PPC_REG_CR27,
		PPC_REG_CR31, };

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif
