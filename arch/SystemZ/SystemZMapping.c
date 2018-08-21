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
static const name_map insn_name_maps[] = {
	{ SYSZ_INS_INVALID, NULL },

#include "SystemZGenInsnNameMaps.inc"
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
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
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
