/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include <stdio.h> // debug
#include <string.h>

#include "../../Mapping.h"
#include "../../cs_priv.h"
#include "../../cs_simple_types.h"
#include "../../utils.h"

#include "AlphaLinkage.h"
#include "AlphaMapping.h"
#include "./AlphaDisassembler.h"

#define GET_INSTRINFO_ENUM

#include "AlphaGenInstrInfo.inc"

static const insn_map insns[] = {
#include "AlphaGenCSMappingInsn.inc"
};

static const map_insn_ops insn_operands[] = {
#include "AlphaGenCSMappingInsnOp.inc"
};

void Alpha_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		memset(get_detail(MI), 0,
			   offsetof(cs_detail, alpha) + sizeof(cs_alpha));
	}
}

void Alpha_add_cs_detail(MCInst *MI, unsigned OpNum)
{
	if (!detail_is_set(MI))
		return;

	cs_op_type op_type = map_get_op_type(MI, OpNum);
	if (op_type == CS_OP_IMM)
		Alpha_set_detail_op_imm(MI, OpNum, ALPHA_OP_IMM,
								MCInst_getOpVal(MI, OpNum));
	else if (op_type == CS_OP_REG)
		Alpha_set_detail_op_reg(MI, OpNum, MCInst_getOpVal(MI, OpNum));
	else
		CS_ASSERT_RET(0 && "Op type not handled.");
}

void Alpha_set_detail_op_imm(MCInst *MI, unsigned OpNum, alpha_op_type ImmType,
							 int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_IMM);
	CS_ASSERT_RET(ImmType == ALPHA_OP_IMM);

	Alpha_get_detail_op(MI, 0)->type = ImmType;
	Alpha_get_detail_op(MI, 0)->imm = Imm;
	Alpha_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Alpha_inc_op_count(MI);
}

void Alpha_set_detail_op_reg(MCInst *MI, unsigned OpNum, alpha_op_type Reg)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET(!(map_get_op_type(MI, OpNum) & CS_OP_MEM));
	CS_ASSERT_RET(map_get_op_type(MI, OpNum) == CS_OP_REG);

	Alpha_get_detail_op(MI, 0)->type = ALPHA_OP_REG;
	Alpha_get_detail_op(MI, 0)->reg = Reg;
	Alpha_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Alpha_inc_op_count(MI);
}

// given internal insn id, return public instruction info
void Alpha_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned short i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i == 0) { return; }
	insn->id = insns[i].mapid;

	if (insn->detail) {
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
#endif
	}
}

#ifndef CAPSTONE_DIET

static const char * const insn_names[] = {
#include "AlphaGenCSMappingInsnName.inc"
};

// special alias insn
// static name_map alias_insn_names[] = {{0, NULL}};
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
static const name_map group_name_maps[] = {
	{Alpha_GRP_INVALID, NULL},
	{Alpha_GRP_CALL, "call"},
	{Alpha_GRP_JUMP, "jump"},
	{Alpha_GRP_BRANCH_RELATIVE, "branch_relative"},
};
#endif

const char *Alpha_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
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
	Alpha_LLVM_printInstruction(MI, O, Info);
}

void Alpha_set_instr_map_data(MCInst *MI) 
{
	map_cs_id(MI, insns, ARR_SIZE(insns));
	map_implicit_reads(MI, insns);
	map_implicit_writes(MI, insns);
	map_groups(MI, insns);
}

bool Alpha_getInstruction(csh handle, const uint8_t *code,
								  size_t code_len, MCInst *instr,
								  uint16_t *size, uint64_t address, void *info)
{
	Alpha_init_cs_detail(instr);
	bool Result = Alpha_LLVM_getInstruction(handle, code, code_len, instr, size,
									 address, info);
	Alpha_set_instr_map_data(instr);
	return Result;
}

#endif
