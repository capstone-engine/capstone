/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_ARM64

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "AArch64Mapping.h"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
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
	if (reg >= ARR_SIZE(reg_name_maps))
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

#include "AArch64MappingInsn.inc"
};

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
			insn->detail->groups_count = (uint8_t)count_positive8(insns[i].groups);

			insn->detail->arm64.update_flags = cs_reg_write((csh)&handle, insn, ARM64_REG_NZCV);
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[] = {
	{ ARM64_INS_INVALID, NULL },

#include "AArch64GenInsnNameMaps.inc"
};

// map *S & alias instructions back to original id
static const name_map alias_insn_name_maps[] = {
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
#endif

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
static const name_map group_name_maps[] = {
	// generic groups
	{ ARM64_GRP_INVALID, NULL },
	{ ARM64_GRP_JUMP, "jump" },
	{ ARM64_GRP_CALL, "call" },
	{ ARM64_GRP_RET, "return" },
	{ ARM64_GRP_PRIVILEGE, "privilege" },
	{ ARM64_GRP_INT, "int" },
	{ ARM64_GRP_BRANCH_RELATIVE, "branch_relative" },

	// architecture-specific groups
	{ ARM64_GRP_CRYPTO, "crypto" },
	{ ARM64_GRP_FPARMV8, "fparmv8" },
	{ ARM64_GRP_NEON, "neon" },
	{ ARM64_GRP_CRC, "crc" },

	// new
	{ ARM64_GRP_HASAES, "hasaes" },
	{ ARM64_GRP_HASCRC, "hascrc" },
	{ ARM64_GRP_HASDOTPROD, "hasdotprod" },
	{ ARM64_GRP_HASFPARMV8, "hasfparmv8" },
	{ ARM64_GRP_HASFULLFP16, "hasfullfp16" },
	{ ARM64_GRP_HASLSE, "haslse" },
	{ ARM64_GRP_HASNEON, "hasneon" },
	{ ARM64_GRP_HASRCPC, "hasrcpc" },
	{ ARM64_GRP_HASRDM, "hasrdm" },
	{ ARM64_GRP_HASSHA2, "hassha2" },
	{ ARM64_GRP_HASSHA3, "hassha3" },
	{ ARM64_GRP_HASSM4, "hassm4" },
	{ ARM64_GRP_HASSVE, "hassve" },
	{ ARM64_GRP_HASV8_1A, "hasv8_1a" },
	{ ARM64_GRP_HASV8_3A, "hasv8_3a" },
	{ ARM64_GRP_HASV8_4A, "hasv8_4a" },
};
#endif

const char *AArch64_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
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
	static const unsigned int map[] = { 0,
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

#ifndef CAPSTONE_DIET

// map instruction to its characteristics
typedef struct insn_op {
	unsigned int eflags_update;	// how this instruction update status flags
	uint8_t access[5];
} insn_op;

static insn_op insn_ops[] = {
    {
         /* NULL item */
        0, { 0 }
    },

#include "AArch64MappingInsnOp.inc"
};

// given internal insn id, return operand access info
uint8_t *AArch64_get_op_access(cs_struct *h, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		return insn_ops[i].access;
	}

	return NULL;
}

void AArch64_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arm64 *arm64 = &(insn->detail->arm64);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read, read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write, write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &(arm64->operands[i]);
		switch((int)op->type) {
			case ARM64_OP_REG:
				if ((op->access & CS_AC_READ) && !arr_exist(regs_read, read_count, op->reg)) {
					regs_read[read_count] = (uint16_t)op->reg;
					read_count++;
				}
				if ((op->access & CS_AC_WRITE) && !arr_exist(regs_write, write_count, op->reg)) {
					regs_write[write_count] = (uint16_t)op->reg;
					write_count++;
				}
				break;
			case ARM_OP_MEM:
				// registers appeared in memory references always being read
				if ((op->mem.base != ARM64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != ARM64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((arm64->writeback) && (op->mem.base != ARM64_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
					regs_write[write_count] = (uint16_t)op->mem.base;
					write_count++;
				}
			default:
				break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

#endif