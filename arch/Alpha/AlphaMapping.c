/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include <stdio.h> // debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"

#include "AlphaLinkage.h"
#include "AlphaMapping.h"

#define GET_INSTRINFO_ENUM

#include "AlphaGenInstrInfo.inc"

static insn_map insns[] = {
#include "AlphaGenCSMappingInsn.inc"
};

// unsigned int Alpha_map_insn_id(cs_struct *h, unsigned int id)
// {
// 	unsigned short i =
// 		insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
// 	if (i != 0) {
// 		return insns[i].mapid;
// 	}
// 	return 0;
// }

// given internal insn id, return public instruction info
void Alpha_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned short i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use,
			       sizeof(insns[i].regs_use));
			insn->detail->regs_read_count =
				(uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod,
			       sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count =
				(uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups,
			       sizeof(insns[i].groups));
			insn->detail->groups_count =
				(uint8_t)count_positive8(insns[i].groups);

			// if (insns[i].branch || insns[i].indirect_branch) {
			// 	// this insn also belongs to JUMP group. add JUMP group
			// 	insn->detail
			// 		->groups[insn->detail->groups_count] =
			// 		Alpha_GRP_JUMP;
			// 	insn->detail->groups_count++;
			// }
#endif
		}
	}
}

#ifndef CAPSTONE_DIET

static const char *insn_names[] = {
#include "AlphaGenCSMappingInsnName.inc"
};

// special alias insn
static name_map alias_insn_names[] = { { 0, NULL } };
#endif

const char *Alpha_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ALPHA_INS_ENDING)
		return NULL;

	if (id < ARR_SIZE(insn_names))
		return insn_names[id];

	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static name_map group_name_maps[] = {
	{ Alpha_GRP_INVALID, NULL },
	{ Alpha_GRP_CALL, "call" },
	{ Alpha_GRP_JUMP, "jump" },
};
#endif

const char *Alpha_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

const char *Alpha_getRegisterName(csh handle, unsigned int id) 
{
	return Alpha_LLVM_getRegisterName(handle, id);
}

void Alpha_printInst(MCInst *MI, SStream *O, void *Info) 
{
	return Alpha_LLVM_printInst(MI, O, Info);
}


#endif