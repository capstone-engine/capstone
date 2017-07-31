/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SYSZ

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "SystemZMapping.h"

#define GET_INSTRINFO_ENUM
#include "SystemZGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static name_map reg_name_maps[] = {
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

static insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

#include "SystemZMappingInsn.inc"
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
			insn->detail->groups_count = (uint8_t)count_positive8(insns[i].groups);

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
static name_map insn_name_maps[] = {
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
static name_map alias_insn_names[] = {
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
static name_map group_name_maps[] = {
	// generic groups
	{ SYSZ_GRP_INVALID, NULL },
	{ SYSZ_GRP_JUMP, "jump" },
	{ SYSZ_GRP_BRANCH_RELATIVE, "branch_relative" },

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
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// map internal raw register to 'public' register
sysz_reg SystemZ_map_register(unsigned int r)
{
	static unsigned int map[] = { 0,
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
