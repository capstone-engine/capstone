/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org> 2022-2023 */

#ifdef CAPSTONE_HAS_SYSTEMZ

#include <stdio.h>	// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"
#include <capstone/cs_operand.h>

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

static const map_insn_ops insn_operands[] = {
#include "SystemZGenCSMappingInsnOp.inc"
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
	const systemz_suppl_info *suppl_info =
		map_get_suppl_info(MI, systemz_insns);
	if (suppl_info) {
		SystemZ_get_detail(MI)->format = suppl_info->form;
	}
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
	if (!detail_is_set(MI)) {
		return;
	}
	memset(get_detail(MI), 0, sizeof(cs_detail));
	if (detail_is_set(MI)) {
		SystemZ_get_detail(MI)->cc = SYSTEMZ_CC_INVALID;
	}
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

void SystemZ_add_cs_detail(MCInst *MI, int /* aarch64_op_group */ op_group,
			   va_list args)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	unsigned op_num = va_arg(args, unsigned);

	switch (op_group) {
	default:
		printf("Operand group %d not handled\n", op_group);
		break;
	case SystemZ_OP_GROUP_Operand: {
		cs_op_type secondary_op_type = map_get_op_type(MI, op_num) &
							 ~(CS_OP_MEM | CS_OP_BOUND);
		if (secondary_op_type == CS_OP_IMM) {
			SystemZ_set_detail_op_imm(MI, op_num,
								MCInst_getOpVal(MI, op_num), 0);
		} else if (secondary_op_type == CS_OP_REG) {
			SystemZ_set_detail_op_reg(MI, op_num,
								MCInst_getOpVal(MI, op_num));
		} else {
			CS_ASSERT_RET(0 && "Op type not handled.");
		}
		break;
	}
	case SystemZ_OP_GROUP_Cond4Operand: {
		systemz_cc cc = MCInst_getOpVal(MI, op_num);
		SystemZ_get_detail(MI)->cc = cc;
		break;
	}
	case SystemZ_OP_GROUP_BDAddrOperand:
		CS_ASSERT_RET(map_get_op_type(MI, (op_num)) & CS_OP_MEM);
		CS_ASSERT_RET(map_get_op_type(MI, (op_num + 1)) & CS_OP_MEM);
		CS_ASSERT_RET(MCOperand_isReg(MCInst_getOperand(MI, (op_num))));
		CS_ASSERT_RET(MCOperand_isImm(MCInst_getOperand(MI, (op_num + 1))));
		SystemZ_set_detail_op_mem(MI,
															op_num,
															MCInst_getOpVal(MI, (op_num)),
															MCInst_getOpVal(MI, (op_num + 1)),
															0,
															0,
															SYSTEMZ_AM_BD
														);
		break;
	case SystemZ_OP_GROUP_BDVAddrOperand:
	case SystemZ_OP_GROUP_BDXAddrOperand: {
		CS_ASSERT(map_get_op_type(MI, (op_num)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 1)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 2)) & CS_OP_MEM);
		CS_ASSERT(MCOperand_isReg(MCInst_getOperand(MI, (op_num))));
		CS_ASSERT(MCOperand_isImm(MCInst_getOperand(MI, (op_num + 1))));
		CS_ASSERT(MCOperand_isReg(MCInst_getOperand(MI, (op_num + 2))));
		SystemZ_set_detail_op_mem(MI,
															op_num,
															MCInst_getOpVal(MI, (op_num)),
															MCInst_getOpVal(MI, (op_num + 1)),
															0,
															MCInst_getOpVal(MI, (op_num + 2)),
															(op_group == SystemZ_OP_GROUP_BDXAddrOperand ? SYSTEMZ_AM_BDX : SYSTEMZ_AM_BDV)
														);
		break;
	}
	case SystemZ_OP_GROUP_BDLAddrOperand:
		CS_ASSERT(map_get_op_type(MI, (op_num)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 1)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 2)) & CS_OP_MEM);
		CS_ASSERT(MCOperand_isReg(MCInst_getOperand(MI, (op_num))));
		CS_ASSERT(MCOperand_isImm(MCInst_getOperand(MI, (op_num + 1))));
		CS_ASSERT(MCOperand_isImm(MCInst_getOperand(MI, (op_num + 2))));
		SystemZ_set_detail_op_mem(MI,
															op_num,
															MCInst_getOpVal(MI, (op_num)),
															MCInst_getOpVal(MI, (op_num + 1)),
					                    MCInst_getOpVal(MI, (op_num + 2)),
		                          0,
		                          SYSTEMZ_AM_BDL
		                        );
		break;
  case SystemZ_OP_GROUP_BDRAddrOperand:
		CS_ASSERT(map_get_op_type(MI, (op_num)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 1)) & CS_OP_MEM);
		CS_ASSERT(map_get_op_type(MI, (op_num + 2)) & CS_OP_MEM);
		CS_ASSERT(MCOperand_isReg(MCInst_getOperand(MI, (op_num))));
		CS_ASSERT(MCOperand_isImm(MCInst_getOperand(MI, (op_num + 1))));
		CS_ASSERT(MCOperand_isReg(MCInst_getOperand(MI, (op_num + 2))));
		SystemZ_set_detail_op_mem(MI,
		                          op_num,
		                          MCInst_getOpVal(MI, (op_num)),
		                          MCInst_getOpVal(MI, (op_num + 1)),
		                          MCInst_getOpVal(MI, (op_num + 2)),
		                          0,
		                          SYSTEMZ_AM_BDL
		                        );
		break;
  case SystemZ_OP_GROUP_PCRelOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 0);
		break;
  case SystemZ_OP_GROUP_U1ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 1);
		break;
  case SystemZ_OP_GROUP_U2ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 2);
		break;
  case SystemZ_OP_GROUP_U3ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 3);
		break;
  case SystemZ_OP_GROUP_U4ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 4);
		break;
  case SystemZ_OP_GROUP_U8ImmOperand:
  case SystemZ_OP_GROUP_S8ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 8);
		break;
  case SystemZ_OP_GROUP_U12ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 12);
		break;
  case SystemZ_OP_GROUP_U16ImmOperand:
  case SystemZ_OP_GROUP_S16ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 16);
		break;
  case SystemZ_OP_GROUP_U32ImmOperand:
  case SystemZ_OP_GROUP_S32ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 32);
		break;
  case SystemZ_OP_GROUP_U48ImmOperand:
			SystemZ_set_detail_op_imm(MI, op_num,
						    MCInst_getOpVal(MI, op_num), 48);
		break;
	}
#endif
}

#ifndef CAPSTONE_DIET

void SystemZ_set_detail_op_imm(MCInst *MI, unsigned op_num, int64_t Imm, size_t width)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT((map_get_op_type(MI, op_num) & ~CS_OP_MEM) == CS_OP_IMM);

	SystemZ_get_detail_op(MI, 0)->type = SYSTEMZ_OP_IMM;
	SystemZ_get_detail_op(MI, 0)->imm = Imm;
	SystemZ_get_detail_op(MI, 0)->access = map_get_op_access(MI, op_num);
	SystemZ_get_detail_op(MI, 0)->imm_width = width;
	SystemZ_inc_op_count(MI);
}

void SystemZ_set_detail_op_reg(MCInst *MI, unsigned op_num, systemz_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT((map_get_op_type(MI, op_num) & ~CS_OP_MEM) == CS_OP_REG);

	SystemZ_get_detail_op(MI, 0)->type = SYSTEMZ_OP_REG;
	SystemZ_get_detail_op(MI, 0)->reg = Reg;
	SystemZ_get_detail_op(MI, 0)->access = map_get_op_access(MI, op_num);
	SystemZ_inc_op_count(MI);
}

void SystemZ_set_detail_op_mem(MCInst *MI, unsigned op_num, systemz_reg base, int64_t disp, uint64_t length, systemz_reg index, systemz_addr_mode am)
{
	if (!detail_is_set(MI))
		return;
	SystemZ_get_detail_op(MI, 0)->type = SYSTEMZ_OP_MEM;
	SystemZ_get_detail_op(MI, 0)->access = map_get_op_access(MI, op_num);
	SystemZ_get_detail_op(MI, 0)->mem.am = am;
	switch(am) {
	default:
		CS_ASSERT(0 && "Address mode not handled\n");
		break;
	case SYSTEMZ_AM_BD:
		SystemZ_get_detail_op(MI, 0)->mem.base = base;
		SystemZ_get_detail_op(MI, 0)->mem.disp = disp;
		break;
	case SYSTEMZ_AM_BDX:
	case SYSTEMZ_AM_BDV:
		SystemZ_get_detail_op(MI, 0)->mem.base = base;
		SystemZ_get_detail_op(MI, 0)->mem.disp = disp;
		SystemZ_get_detail_op(MI, 0)->mem.index = index;
		break;
	case SYSTEMZ_AM_BDL:
		SystemZ_get_detail_op(MI, 0)->mem.base = base;
		SystemZ_get_detail_op(MI, 0)->mem.disp = disp;
		SystemZ_get_detail_op(MI, 0)->mem.length = length;
		break;
	case SYSTEMZ_AM_BDR:
		SystemZ_get_detail_op(MI, 0)->mem.base = base;
		SystemZ_get_detail_op(MI, 0)->mem.disp = disp;
		SystemZ_get_detail_op(MI, 0)->mem.length = length;
		break;
	}
	SystemZ_inc_op_count(MI);
}

#endif

#endif
