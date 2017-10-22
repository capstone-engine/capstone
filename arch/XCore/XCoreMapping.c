/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_XCORE

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "XCoreMapping.h"

#define GET_INSTRINFO_ENUM
#include "XCoreGenInstrInfo.inc"

static const name_map reg_name_maps[] = {
	{ XCORE_REG_INVALID, NULL },

	{ XCORE_REG_CP, "cp" },
	{ XCORE_REG_DP, "dp" },
	{ XCORE_REG_LR, "lr" },
	{ XCORE_REG_SP, "sp" },
	{ XCORE_REG_R0, "r0" },
	{ XCORE_REG_R1, "r1" },
	{ XCORE_REG_R2, "r2" },
	{ XCORE_REG_R3, "r3" },
	{ XCORE_REG_R4, "r4" },
	{ XCORE_REG_R5, "r5" },
	{ XCORE_REG_R6, "r6" },
	{ XCORE_REG_R7, "r7" },
	{ XCORE_REG_R8, "r8" },
	{ XCORE_REG_R9, "r9" },
	{ XCORE_REG_R10, "r10" },
	{ XCORE_REG_R11, "r11" },

	// pseudo registers
	{ XCORE_REG_PC, "pc" },

	{ XCORE_REG_SCP, "scp" },
	{ XCORE_REG_SSR, "ssr" },
	{ XCORE_REG_ET, "et" },
	{ XCORE_REG_ED, "ed" },
	{ XCORE_REG_SED, "sed" },
	{ XCORE_REG_KEP, "kep" },
	{ XCORE_REG_KSP, "ksp" },
	{ XCORE_REG_ID, "id" },
};

const char *XCore_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= XCORE_REG_ENDING)
		return NULL;

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

xcore_reg XCore_reg_id(char *name)
{
	int i;

	for(i = 1; i < ARR_SIZE(reg_name_maps); i++) {
		if (!strcmp(name, reg_name_maps[i].name))
			return reg_name_maps[i].id;
	}

	// not found
	return 0;
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
		XCore_ADD_2rus, XCORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ADD_3r, XCORE_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ANDNOT_2r, XCORE_INS_ANDNOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_AND_3r, XCORE_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ASHR_l2rus, XCORE_INS_ASHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ASHR_l3r, XCORE_INS_ASHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BAU_1r, XCORE_INS_BAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_BITREV_l2r, XCORE_INS_BITREV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLACP_lu10, XCORE_INS_BLA,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLACP_u10, XCORE_INS_BLA,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLAT_lu6, XCORE_INS_BLAT,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_R11, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLAT_u6, XCORE_INS_BLAT,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_R11, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLA_1r, XCORE_INS_BLA,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLRB_lu10, XCORE_INS_BL,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLRB_u10, XCORE_INS_BL,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLRF_lu10, XCORE_INS_BL,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BLRF_u10, XCORE_INS_BL,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_R0, XCORE_REG_R1, XCORE_REG_R2, XCORE_REG_R3, XCORE_REG_R11, XCORE_REG_LR, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_BRBF_lru6, XCORE_INS_BF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRBF_ru6, XCORE_INS_BF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRBT_lru6, XCORE_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRBT_ru6, XCORE_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRBU_lu6, XCORE_INS_BU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRBU_u6, XCORE_INS_BU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFF_lru6, XCORE_INS_BF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFF_ru6, XCORE_INS_BF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFT_lru6, XCORE_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFT_ru6, XCORE_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFU_lu6, XCORE_INS_BU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRFU_u6, XCORE_INS_BU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		XCore_BRU_1r, XCORE_INS_BRU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_BYTEREV_l2r, XCORE_INS_BYTEREV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CHKCT_2r, XCORE_INS_CHKCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CHKCT_rus, XCORE_INS_CHKCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CLRE_0R, XCORE_INS_CLRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CLRPT_1R, XCORE_INS_CLRPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CLRSR_branch_lu6, XCORE_INS_CLRSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_CLRSR_branch_u6, XCORE_INS_CLRSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_CLRSR_lu6, XCORE_INS_CLRSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CLRSR_u6, XCORE_INS_CLRSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CLZ_l2r, XCORE_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CRC8_l4r, XCORE_INS_CRC8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_CRC_l3r, XCORE_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DCALL_0R, XCORE_INS_DCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DENTSP_0R, XCORE_INS_DENTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DGETREG_1r, XCORE_INS_DGETREG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DIVS_l3r, XCORE_INS_DIVS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DIVU_l3r, XCORE_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DRESTSP_0R, XCORE_INS_DRESTSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_DRET_0R, XCORE_INS_DRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ECALLF_1r, XCORE_INS_ECALLF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ECALLT_1r, XCORE_INS_ECALLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EDU_1r, XCORE_INS_EDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EEF_2r, XCORE_INS_EEF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EET_2r, XCORE_INS_EET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EEU_1r, XCORE_INS_EEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ENDIN_2r, XCORE_INS_ENDIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ENTSP_lu6, XCORE_INS_ENTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ENTSP_u6, XCORE_INS_ENTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EQ_2rus, XCORE_INS_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EQ_3r, XCORE_INS_EQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EXTDP_lu6, XCORE_INS_EXTDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EXTDP_u6, XCORE_INS_EXTDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EXTSP_lu6, XCORE_INS_EXTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_EXTSP_u6, XCORE_INS_EXTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_FREER_1r, XCORE_INS_FREER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_FREET_0R, XCORE_INS_FREET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETD_l2r, XCORE_INS_GETD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETED_0R, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETET_0R, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETID_0R, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETKEP_0R, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETKSP_0R, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETN_l2r, XCORE_INS_GETN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETPS_l2r, XCORE_INS_GET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETR_rus, XCORE_INS_GETR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETSR_lu6, XCORE_INS_GETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETSR_u6, XCORE_INS_GETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETST_2r, XCORE_INS_GETST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_GETTS_2r, XCORE_INS_GETTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INCT_2r, XCORE_INS_INCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INITCP_2r, XCORE_INS_INIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INITDP_2r, XCORE_INS_INIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INITLR_l2r, XCORE_INS_INIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INITPC_2r, XCORE_INS_INIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INITSP_2r, XCORE_INS_INIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INPW_l2rus, XCORE_INS_INPW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INSHR_2r, XCORE_INS_INSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_INT_2r, XCORE_INS_INT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_IN_2r, XCORE_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KCALL_1r, XCORE_INS_KCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KCALL_lu6, XCORE_INS_KCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KCALL_u6, XCORE_INS_KCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KENTSP_lu6, XCORE_INS_KENTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KENTSP_u6, XCORE_INS_KENTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KRESTSP_lu6, XCORE_INS_KRESTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KRESTSP_u6, XCORE_INS_KRESTSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_KRET_0R, XCORE_INS_KRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LADD_l5r, XCORE_INS_LADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LD16S_3r, XCORE_INS_LD16S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LD8U_3r, XCORE_INS_LD8U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDA16B_l3r, XCORE_INS_LDA16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDA16F_l3r, XCORE_INS_LDA16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAPB_lu10, XCORE_INS_LDAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAPB_u10, XCORE_INS_LDAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAPF_lu10, XCORE_INS_LDAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAPF_lu10_ba, XCORE_INS_LDAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAPF_u10, XCORE_INS_LDAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWB_l2rus, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWB_l3r, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWCP_lu6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWCP_u6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWDP_lru6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWDP_ru6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWF_l2rus, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWF_l3r, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWSP_lru6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDAWSP_ru6, XCORE_INS_LDAW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDC_lru6, XCORE_INS_LDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDC_ru6, XCORE_INS_LDC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDET_0R, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDIVU_l5r, XCORE_INS_LDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDSED_0R, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDSPC_0R, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDSSR_0R, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWCP_lru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWCP_lu10, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWCP_ru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWCP_u10, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_R11, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWDP_lru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWDP_ru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWSP_lru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDWSP_ru6, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDW_2rus, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LDW_3r, XCORE_INS_LDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LMUL_l6r, XCORE_INS_LMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LSS_3r, XCORE_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LSUB_l5r, XCORE_INS_LSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_LSU_3r, XCORE_INS_LSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MACCS_l4r, XCORE_INS_MACCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MACCU_l4r, XCORE_INS_MACCU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MJOIN_1r, XCORE_INS_MJOIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MKMSK_2r, XCORE_INS_MKMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MKMSK_rus, XCORE_INS_MKMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MSYNC_1r, XCORE_INS_MSYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_MUL_l3r, XCORE_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_NEG, XCORE_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_NOT, XCORE_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OR_3r, XCORE_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUTCT_2r, XCORE_INS_OUTCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUTCT_rus, XCORE_INS_OUTCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUTPW_l2rus, XCORE_INS_OUTPW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUTSHR_2r, XCORE_INS_OUTSHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUTT_2r, XCORE_INS_OUTT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_OUT_2r, XCORE_INS_OUT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_PEEK_2r, XCORE_INS_PEEK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_REMS_l3r, XCORE_INS_REMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_REMU_l3r, XCORE_INS_REMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_RETSP_lu6, XCORE_INS_RETSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_RETSP_u6, XCORE_INS_RETSP,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETCLK_l2r, XCORE_INS_SETCLK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETCP_1r, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETC_l2r, XCORE_INS_SETC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETC_lru6, XCORE_INS_SETC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETC_ru6, XCORE_INS_SETC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETDP_1r, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETD_2r, XCORE_INS_SETD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETEV_1r, XCORE_INS_SETEV,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_R11, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETKEP_0R, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_R11, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETN_l2r, XCORE_INS_SETN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETPSC_2r, XCORE_INS_SETPSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETPS_l2r, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETPT_2r, XCORE_INS_SETPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETRDY_l2r, XCORE_INS_SETRDY,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETSP_1r, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ 0 }, { XCORE_REG_SP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETSR_branch_lu6, XCORE_INS_SETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_SETSR_branch_u6, XCORE_INS_SETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_SETSR_lu6, XCORE_INS_SETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETSR_u6, XCORE_INS_SETSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETTW_l2r, XCORE_INS_SETTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SETV_1r, XCORE_INS_SETV,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_R11, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SEXT_2r, XCORE_INS_SEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SEXT_rus, XCORE_INS_SEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SHL_2rus, XCORE_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SHL_3r, XCORE_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SHR_2rus, XCORE_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SHR_3r, XCORE_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SSYNC_0r, XCORE_INS_SSYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ST16_l3r, XCORE_INS_ST16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ST8_l3r, XCORE_INS_ST8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STET_0R, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STSED_0R, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STSPC_0R, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STSSR_0R, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STWDP_lru6, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STWDP_ru6, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STWSP_lru6, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STWSP_ru6, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ XCORE_REG_SP, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STW_2rus, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_STW_l3r, XCORE_INS_STW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SUB_2rus, XCORE_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SUB_3r, XCORE_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_SYNCR_1r, XCORE_INS_SYNCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TESTCT_2r, XCORE_INS_TESTCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TESTLCL_l2r, XCORE_INS_TESTLCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TESTWCT_2r, XCORE_INS_TESTWCT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TSETMR_2r, XCORE_INS_TSETMR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TSETR_3r, XCORE_INS_SET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_TSTART_1R, XCORE_INS_START,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_WAITEF_1R, XCORE_INS_WAITEF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_WAITET_1R, XCORE_INS_WAITET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_WAITEU_0R, XCORE_INS_WAITEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		XCore_XOR_l3r, XCORE_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ZEXT_2r, XCORE_INS_ZEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		XCore_ZEXT_rus, XCORE_INS_ZEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
};

// given internal insn id, return public instruction info
void XCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
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
				insn->detail->groups[insn->detail->groups_count] = XCORE_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[] = {
	{ XCORE_INS_INVALID, NULL },

	{ XCORE_INS_ADD, "add" },
	{ XCORE_INS_ANDNOT, "andnot" },
	{ XCORE_INS_AND, "and" },
	{ XCORE_INS_ASHR, "ashr" },
	{ XCORE_INS_BAU, "bau" },
	{ XCORE_INS_BITREV, "bitrev" },
	{ XCORE_INS_BLA, "bla" },
	{ XCORE_INS_BLAT, "blat" },
	{ XCORE_INS_BL, "bl" },
	{ XCORE_INS_BF, "bf" },
	{ XCORE_INS_BT, "bt" },
	{ XCORE_INS_BU, "bu" },
	{ XCORE_INS_BRU, "bru" },
	{ XCORE_INS_BYTEREV, "byterev" },
	{ XCORE_INS_CHKCT, "chkct" },
	{ XCORE_INS_CLRE, "clre" },
	{ XCORE_INS_CLRPT, "clrpt" },
	{ XCORE_INS_CLRSR, "clrsr" },
	{ XCORE_INS_CLZ, "clz" },
	{ XCORE_INS_CRC8, "crc8" },
	{ XCORE_INS_CRC32, "crc32" },
	{ XCORE_INS_DCALL, "dcall" },
	{ XCORE_INS_DENTSP, "dentsp" },
	{ XCORE_INS_DGETREG, "dgetreg" },
	{ XCORE_INS_DIVS, "divs" },
	{ XCORE_INS_DIVU, "divu" },
	{ XCORE_INS_DRESTSP, "drestsp" },
	{ XCORE_INS_DRET, "dret" },
	{ XCORE_INS_ECALLF, "ecallf" },
	{ XCORE_INS_ECALLT, "ecallt" },
	{ XCORE_INS_EDU, "edu" },
	{ XCORE_INS_EEF, "eef" },
	{ XCORE_INS_EET, "eet" },
	{ XCORE_INS_EEU, "eeu" },
	{ XCORE_INS_ENDIN, "endin" },
	{ XCORE_INS_ENTSP, "entsp" },
	{ XCORE_INS_EQ, "eq" },
	{ XCORE_INS_EXTDP, "extdp" },
	{ XCORE_INS_EXTSP, "extsp" },
	{ XCORE_INS_FREER, "freer" },
	{ XCORE_INS_FREET, "freet" },
	{ XCORE_INS_GETD, "getd" },
	{ XCORE_INS_GET, "get" },
	{ XCORE_INS_GETN, "getn" },
	{ XCORE_INS_GETR, "getr" },
	{ XCORE_INS_GETSR, "getsr" },
	{ XCORE_INS_GETST, "getst" },
	{ XCORE_INS_GETTS, "getts" },
	{ XCORE_INS_INCT, "inct" },
	{ XCORE_INS_INIT, "init" },
	{ XCORE_INS_INPW, "inpw" },
	{ XCORE_INS_INSHR, "inshr" },
	{ XCORE_INS_INT, "int" },
	{ XCORE_INS_IN, "in" },
	{ XCORE_INS_KCALL, "kcall" },
	{ XCORE_INS_KENTSP, "kentsp" },
	{ XCORE_INS_KRESTSP, "krestsp" },
	{ XCORE_INS_KRET, "kret" },
	{ XCORE_INS_LADD, "ladd" },
	{ XCORE_INS_LD16S, "ld16s" },
	{ XCORE_INS_LD8U, "ld8u" },
	{ XCORE_INS_LDA16, "lda16" },
	{ XCORE_INS_LDAP, "ldap" },
	{ XCORE_INS_LDAW, "ldaw" },
	{ XCORE_INS_LDC, "ldc" },
	{ XCORE_INS_LDW, "ldw" },
	{ XCORE_INS_LDIVU, "ldivu" },
	{ XCORE_INS_LMUL, "lmul" },
	{ XCORE_INS_LSS, "lss" },
	{ XCORE_INS_LSUB, "lsub" },
	{ XCORE_INS_LSU, "lsu" },
	{ XCORE_INS_MACCS, "maccs" },
	{ XCORE_INS_MACCU, "maccu" },
	{ XCORE_INS_MJOIN, "mjoin" },
	{ XCORE_INS_MKMSK, "mkmsk" },
	{ XCORE_INS_MSYNC, "msync" },
	{ XCORE_INS_MUL, "mul" },
	{ XCORE_INS_NEG, "neg" },
	{ XCORE_INS_NOT, "not" },
	{ XCORE_INS_OR, "or" },
	{ XCORE_INS_OUTCT, "outct" },
	{ XCORE_INS_OUTPW, "outpw" },
	{ XCORE_INS_OUTSHR, "outshr" },
	{ XCORE_INS_OUTT, "outt" },
	{ XCORE_INS_OUT, "out" },
	{ XCORE_INS_PEEK, "peek" },
	{ XCORE_INS_REMS, "rems" },
	{ XCORE_INS_REMU, "remu" },
	{ XCORE_INS_RETSP, "retsp" },
	{ XCORE_INS_SETCLK, "setclk" },
	{ XCORE_INS_SET, "set" },
	{ XCORE_INS_SETC, "setc" },
	{ XCORE_INS_SETD, "setd" },
	{ XCORE_INS_SETEV, "setev" },
	{ XCORE_INS_SETN, "setn" },
	{ XCORE_INS_SETPSC, "setpsc" },
	{ XCORE_INS_SETPT, "setpt" },
	{ XCORE_INS_SETRDY, "setrdy" },
	{ XCORE_INS_SETSR, "setsr" },
	{ XCORE_INS_SETTW, "settw" },
	{ XCORE_INS_SETV, "setv" },
	{ XCORE_INS_SEXT, "sext" },
	{ XCORE_INS_SHL, "shl" },
	{ XCORE_INS_SHR, "shr" },
	{ XCORE_INS_SSYNC, "ssync" },
	{ XCORE_INS_ST16, "st16" },
	{ XCORE_INS_ST8, "st8" },
	{ XCORE_INS_STW, "stw" },
	{ XCORE_INS_SUB, "sub" },
	{ XCORE_INS_SYNCR, "syncr" },
	{ XCORE_INS_TESTCT, "testct" },
	{ XCORE_INS_TESTLCL, "testlcl" },
	{ XCORE_INS_TESTWCT, "testwct" },
	{ XCORE_INS_TSETMR, "tsetmr" },
	{ XCORE_INS_START, "start" },
	{ XCORE_INS_WAITEF, "waitef" },
	{ XCORE_INS_WAITET, "waitet" },
	{ XCORE_INS_WAITEU, "waiteu" },
	{ XCORE_INS_XOR, "xor" },
	{ XCORE_INS_ZEXT, "zext" },
};

// special alias insn
static const name_map alias_insn_names[] = {
	{ 0, NULL }
};
#endif

const char *XCore_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	unsigned int i;

	if (id >= XCORE_INS_ENDING)
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
	{ XCORE_GRP_INVALID, NULL },
	{ XCORE_GRP_JUMP, "jump" },
};
#endif

const char *XCore_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= XCORE_GRP_ENDING)
		return NULL;

	return group_name_maps[id].name;
#else
	return NULL;
#endif
}

// map internal raw register to 'public' register
xcore_reg XCore_map_register(unsigned int r)
{
	static const unsigned int map[] = { 0,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif
