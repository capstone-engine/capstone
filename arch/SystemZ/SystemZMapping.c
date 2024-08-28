/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org> 2022-2023 */

#ifdef CAPSTONE_HAS_SYSTEMZ

#include <stdio.h>	// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"

#include "SystemZMCTargetDesc.h"
#include "SystemZMapping.h"
#include "SystemZLinkage.h"


#ifndef CAPSTONE_DIET

static const char *const insn_name_maps[] = {
#include "SystemZGenCSMappingInsnName.inc"
};

static const name_map insn_alias_mnem_map[] = {
#include "SystemZGenCSAliasMnemMap.inc"
	{ SYSTEMZ_INS_ALIAS_END, NULL },
};

#endif

#define GET_REGINFO_MC_DESC
#include "SystemZGenRegisterInfo.inc"

const insn_map systemz_insns[] = {
#include "SystemZGenCSMappingInsn.inc"
};

void SystemZ_set_instr_map_data(MCInst *MI, const uint8_t *Bytes, size_t BytesLen)
{
	map_cs_id(MI, systemz_insns, ARR_SIZE(systemz_insns));
	map_implicit_reads(MI, systemz_insns);
	map_implicit_writes(MI, systemz_insns);
	map_groups(MI, systemz_insns);
}

void SystemZ_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, SystemZRegDesc, AARCH64_REG_ENDING, 0, 0,
		SystemZMCRegisterClasses, ARR_SIZE(SystemZMCRegisterClasses), 0,
		0, SystemZRegDiffLists, 0, SystemZSubRegIdxLists,
		ARR_SIZE(SystemZSubRegIdxLists), 0);
}

const char *SystemZ_reg_name(csh handle, unsigned int reg)
{
	return SystemZ_LLVM_getRegisterName(reg);
}

void SystemZ_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info)
{
	MI->MRI = (MCRegisterInfo *)info;
	MI->fillDetailOps = detail_is_set(MI);
	SystemZ_LLVM_printInstruction(MI, "", O);
#ifndef CAPSTONE_DIET
	map_set_alias_id(MI, O, insn_alias_mnem_map,
			 ARR_SIZE(insn_alias_mnem_map));
#endif
}

void SystemZ_init_cs_detail(MCInst *MI) {
	return;
}

bool SystemZ_getInstruction(csh handle, const uint8_t *bytes, size_t bytes_len,
			MCInst *MI, uint16_t *size, uint64_t address,
			void *info)
{
	SystemZ_init_cs_detail(MI);
	MI->MRI = (MCRegisterInfo *)info;
	DecodeStatus result = SystemZ_LLVM_getInstruction(
		handle, bytes, bytes_len, MI, size, address, info);
	SystemZ_set_instr_map_data(MI, bytes, bytes_len);
	return result != MCDisassembler_Fail;
}

// given internal insn id, return public instruction info
void SystemZ_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// We do this after Instruction disassembly.
}

const char *SystemZ_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < SYSTEMZ_INS_ALIAS_END && id > SYSTEMZ_INS_ALIAS_BEGIN) {
		if (id - SYSTEMZ_INS_ALIAS_BEGIN >=
		    ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - SYSTEMZ_INS_ALIAS_BEGIN - 1]
			.name;
	}
	if (id >= SYSTEMZ_INS_ENDING)
		return NULL;

	if (id < ARR_SIZE(insn_name_maps))
		return insn_name_maps[id];

	// not found
	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ SYSTEMZ_GRP_INVALID, NULL },
	{ SYSTEMZ_GRP_JUMP, "jump" },
	{ SYSTEMZ_GRP_CALL, "call" },
	{ SYSTEMZ_GRP_RET, "return" },
	{ SYSTEMZ_GRP_INT, "int" },
	{ SYSTEMZ_GRP_IRET, "iret" },
	{ SYSTEMZ_GRP_PRIVILEGE, "privilege" },
	{ SYSTEMZ_GRP_BRANCH_RELATIVE, "branch_relative" },

	#include "SystemZGenCSFeatureName.inc"
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
