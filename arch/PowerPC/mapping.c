/* Capstone Unified Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>	// debug
#include <string.h>

#include "../../include/ppc.h"
#include "../../utils.h"

#include "mapping.h"

#define GET_INSTRINFO_ENUM
#include "PPCGenInstrInfo.inc"

static name_map reg_name_maps[] = {
	{ PPC_REG_INVALID, NULL },

};

const char *PPC_reg_name(csh handle, unsigned int reg)
{
	if (reg >= PPC_REG_MAX)
		return NULL;

	return reg_name_maps[reg].name;
}

static insn_map insns[] = {
	//{ PPC_ABSQ_S_PH, PPC_INS_ABSQ_S, { 0 }, { PPC_REG_DSPOUTFLAG20, 0 }, { PPC_GRP_DSP, 0 }, 0, 0 },
};

static insn_map alias_insns[] = {
	{ -2, PPC_INS_NOP, { 0 }, { 0 }, { 0 }, 0, 0 },
	{ PPC_SUBu, PPC_INS_NEGU, { 0 }, { 0 }, { PPC_GRP_STDENC, 0 }, 0, 0 },
};

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_insn *insn, unsigned int id, int detail)
{
	int i;

	// consider alias insn first
	for (i = 0; i < ARR_SIZE(alias_insns); i++) {
		if (alias_insns[i].id == id) {
			insn->id = alias_insns[i].mapid;

			if (detail) {
				memcpy(insn->detail->regs_read, alias_insns[i].regs_use, sizeof(alias_insns[i].regs_use));
				insn->detail->regs_read_count = count_positive(alias_insns[i].regs_use);

				memcpy(insn->detail->regs_write, alias_insns[i].regs_mod, sizeof(alias_insns[i].regs_mod));
				insn->detail->regs_write_count = count_positive(alias_insns[i].regs_mod);

				memcpy(insn->detail->groups, alias_insns[i].groups, sizeof(alias_insns[i].groups));
				insn->detail->groups_count = count_positive(alias_insns[i].groups);

				if (alias_insns[i].branch || alias_insns[i].indirect_branch) {
					// this insn also belongs to JUMP group. add JUMP group
					insn->detail->groups[insn->detail->groups_count] = PPC_GRP_JUMP;
					insn->detail->groups_count++;
				}

				return;
			}
		}
	}

	i = insn_find(insns, ARR_SIZE(insns), id);
	if (i != -1) {
		insn->id = insns[i].mapid;

		if (detail) {
			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = count_positive(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = PPC_GRP_JUMP;
				insn->detail->groups_count++;
			}
		}
	}
}

// given public insn id, return internal insn id
unsigned int PPC_get_insn_id2(unsigned int id)
{
	// consider alias insn first
	unsigned int res;
	res = insn_reverse_id(alias_insns, ARR_SIZE(alias_insns), id);
	if (res)
		return res;

	return insn_reverse_id(insns, ARR_SIZE(insns), id);
}

static name_map insn_name_maps[] = {
	{ PPC_INS_INVALID, NULL },

};

// special alias insn
static name_map alias_insn_names[] = {
	{ PPC_INS_NOP, "nop" },
};

const char *PPC_insn_name(csh handle, unsigned int id)
{
	if (id >= PPC_INS_MAX)
		return NULL;

	// handle special alias first
	int i;
	for (i = 0; i < ARR_SIZE(alias_insn_names); i++) {
		if (alias_insn_names[i].id == id)
			return alias_insn_names[i].name;
	}

	return insn_name_maps[id].name;
}

ppc_reg PPC_map_insn(const char *name)
{
	// handle special alias first
	int i;

	for (i = 0; i < ARR_SIZE(alias_insn_names); i++) {
		if (!strcasecmp(alias_insn_names[i].name, name))
			return alias_insn_names[i].id;
	}

	// NOTE: skip first NULL name in insn_name_maps
	i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	return (i != -1)? i : PPC_REG_INVALID;
}

// map internal raw register to 'public' register
ppc_reg PPC_map_register(unsigned int r)
{
	unsigned int map[] = { 0, };

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}
