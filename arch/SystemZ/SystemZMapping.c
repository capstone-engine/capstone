/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SYSZ

#include <stdio.h>	// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"

#include "SystemZMapping.h"

#define GET_INSTRINFO_ENUM
#include "SystemZGenInstrInfo.inc"

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

		if (h->detail_opt) {
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

#endif
