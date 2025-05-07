/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SPARC

#include <stdio.h>	// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"

#include "SparcMapping.h"

void Sparc_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		memset(get_detail(MI), 0,
		       offsetof(cs_detail, arm) + sizeof(cs_arm));
	}
}

const insn_map sparc_insns[] = {
#include "SparcGenCSMappingInsn.inc"
};

void Sparc_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, sparc_insns, ARR_SIZE(sparc_insns));
	map_implicit_reads(MI, sparc_insns);
	map_implicit_writes(MI, sparc_insns);
	map_groups(MI, sparc_insns);
}

bool Sparc_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info)
{
	Sparc_init_cs_detail(instr);
	bool Result = Sparc_LLVM_getInstruction(handle, code, code_len, instr,
					      size, address,
					      info) != MCDisassembler_Fail;
	Sparc_set_instr_map_data(instr);
	return Result;
}

void Sparc_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, SparcRegDesc,
					  sizeof(SparcRegDesc), 0, 0,
					  SparcMCRegisterClasses,
					  ARR_SIZE(SparcMCRegisterClasses),
					  0, 0, SparcRegDiffLists, 0,
					  SparcSubRegIdxLists,
					  ARR_SIZE(SparcSubRegIdxLists), 0);
}

const char *Sparc_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;

	if (syntax_opt & CS_OPT_SYNTAX_NOREGNAME) {
		return Sparc_LLVM_getRegisterName(reg,
						      Sparc_NoRegAltName);
	}
	return Sparc_LLVM_getRegisterName(reg, Sparc_RegNamesStateReg);
}

void Sparc_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by Sparc. Information is set after disassembly.
}

static const char *const insn_name_maps[] = {
#include "SparcGenCSMappingInsnName.inc"
};

#ifndef CAPSTONE_DIET
static const name_map insn_alias_mnem_map[] = {
#include "SparcGenCSAliasMnemMap.inc"
	{ SPARC_INS_ALIAS_END, NULL },
};
#endif

void Sparc_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	Sparc_LLVM_printInst(MI, MI->address, "", O);

#ifndef CAPSTONE_DIET
	map_set_alias_id(MI, O, insn_alias_mnem_map,
			 ARR_SIZE(insn_alias_mnem_map));
#endif
}

const char *Sparc_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < SPARC_INS_ALIAS_END && id > SPARC_INS_ALIAS_BEGIN) {
		if (id - SPARC_INS_ALIAS_BEGIN >=
		    ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - SPARC_INS_ALIAS_BEGIN - 1]
			.name;
	}
	if (id >= SPARC_INS_ENDING)
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
	{ SPARC_GRP_INVALID, NULL },

	{ SPARC_GRP_JUMP, "jump" },
	{ SPARC_GRP_CALL, "call" },
	{ SPARC_GRP_RET, "return" },
	{ SPARC_GRP_INT, "int" },
	{ SPARC_GRP_IRET, "iret" },
	{ SPARC_GRP_PRIVILEGE, "privilege" },
	{ SPARC_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture-specific groups
#include "SparcGenCSFeatureName.inc"
};
#endif

const char *Sparc_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

static const map_insn_ops insn_operands[] = {
#include "SparcGenCSMappingInsnOp.inc"
};

void Sparc_set_detail_op_imm(MCInst *MI, unsigned OpNum,
				 sparc_op_type ImmType, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
	CS_ASSERT_RET(ImmType == SPARC_OP_IMM);

	Sparc_get_detail_op(MI, 0)->type = ImmType;
	Sparc_get_detail_op(MI, 0)->imm = Imm;
	Sparc_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Sparc_inc_op_count(MI);
}

void Sparc_set_detail_op_reg(MCInst *MI, unsigned OpNum, sparc_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	Sparc_get_detail_op(MI, 0)->type = SPARC_OP_REG;
	Sparc_get_detail_op(MI, 0)->reg = Reg;
	Sparc_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Sparc_inc_op_count(MI);
}

void Sparc_add_cs_detail_0(MCInst *MI, sparc_op_group op_group, unsigned OpNo)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	cs_op_type op_type = map_get_op_type(MI, OpNo) & ~CS_OP_MEM;

	switch (op_group) {
	default:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case Sparc_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			Sparc_set_detail_op_imm(MI, OpNo, SPARC_OP_IMM,
						    MCInst_getOpVal(MI, OpNo));
		} else if (op_type == CS_OP_REG) {
			Sparc_set_detail_op_reg(MI, OpNo,
						    MCInst_getOpVal(MI, OpNo));
		} else {
			CS_ASSERT_RET(0 && "Op type not handled.");
		}
		break;
	case Sparc_OP_GROUP_MemOperand:
	case Sparc_OP_GROUP_GetPCX:
	case Sparc_OP_GROUP_CCOperand:
	case Sparc_OP_GROUP_ASITag:
	case Sparc_OP_GROUP_MembarTag:
		return;
	}
}

#endif
