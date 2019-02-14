/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#include "BPFMapping.h"
#include "../../utils.h"

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ BPF_GRP_INVALID, NULL },
	{ BPF_GRP_LOAD, "load" },
	{ BPF_GRP_STORE, "store" },
	{ BPF_GRP_ALU, "alu" },
	{ BPF_GRP_JUMP, "jump" },
	{ BPF_GRP_CALL, "call" },
	{ BPF_GRP_RETURN, "return" },
	{ BPF_GRP_MISC, "misc" },
};
#endif

const char *BPF_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[BPF_INS_ENDING] = {
	{ BPF_INS_INVALID, NULL },

	{ BPF_INS_LDABSB, "ldabsb" },

	{ BPF_INS_RET, "ret" },
};
#endif

const char *BPF_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(insn_name_maps, ARR_SIZE(insn_name_maps), id);
#else
	return NULL;
#endif
}

const char *BPF_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (EBPF_MODE(handle)) {
		if (reg < BPF_REG_R0 || reg > BPF_REG_R10)
			return NULL;
		static const char* reg_names[11] = {
			"r0", "r1", "r2", "r3", "r4",
			"r5", "r6", "r7", "r8", "r9",
			"r10"
		};
		return reg_names[reg - BPF_REG_R0];
	}

	/* cBPF mode */
	if (reg == BPF_REG_A)
		return "A";
	else if (reg == BPF_REG_X)
		return "X";
	else
		return NULL;
#else
	return NULL;
#endif
}

void BPF_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = id;
}
