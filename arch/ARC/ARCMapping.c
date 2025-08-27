/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

#ifdef CAPSTONE_HAS_ARC

#include <stdio.h>
#include <string.h>

#include <capstone/capstone.h>
#include <capstone/arc.h>

#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../cs_priv.h"
#include "../../cs_simple_types.h"

#include "ARCMapping.h"
#include "ARCLinkage.h"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "ARCGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "ARCGenInstrInfo.inc"

void ARC_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, ARCRegDesc, sizeof(ARCRegDesc),
					  0, 0, ARCMCRegisterClasses,
					  ARR_SIZE(ARCMCRegisterClasses), 0, 0,
					  ARCRegDiffLists, 0, ARCSubRegIdxLists,
					  ARR_SIZE(ARCSubRegIdxLists), 0);
}

const char *ARC_reg_name(csh handle, unsigned int reg)
{
	return ARC_LLVM_getRegisterName(reg);
}

void ARC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by ARC. Information is set after disassembly.
}

static const char *const insn_name_maps[] = {
#include "ARCGenCSMappingInsnName.inc"
};

const char *ARC_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
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
	{ ARC_GRP_INVALID, NULL },

	{ ARC_GRP_JUMP, "jump" },
	{ ARC_GRP_CALL, "call" },
	{ ARC_GRP_RET, "return" },
	{ ARC_GRP_BRANCH_RELATIVE, "branch_relative" },

};
#endif

const char *ARC_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

void ARC_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arc *arc = &(insn->detail->arc);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arc->op_count; i++) {
		cs_arc_op *op = &(arc->operands[i]);
		switch ((int)op->type) {
		case ARC_OP_REG:
			if ((op->access & CS_AC_READ) &&
			    !arr_exist(regs_read, read_count, op->reg)) {
				regs_read[read_count] = (uint16_t)op->reg;
				read_count++;
			}
			if ((op->access & CS_AC_WRITE) &&
			    !arr_exist(regs_write, write_count, op->reg)) {
				regs_write[write_count] = (uint16_t)op->reg;
				write_count++;
			}
			break;
		default:
			break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}

const insn_map arc_insns[] = {
#include "ARCGenCSMappingInsn.inc"
};

void ARC_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, arc_insns, ARR_SIZE(arc_insns));
	map_implicit_reads(MI, arc_insns);
	map_implicit_writes(MI, arc_insns);
	map_groups(MI, arc_insns);
}

bool ARC_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info)
{
	uint64_t temp_size;
	ARC_init_cs_detail(instr);
	DecodeStatus Result = ARC_LLVM_getInstruction(instr, &temp_size, code,
						      code_len, address, info);
	ARC_set_instr_map_data(instr);
	*size = temp_size;
	if (Result == MCDisassembler_SoftFail) {
		MCInst_setSoftFail(instr);
	}
	return Result != MCDisassembler_Fail;
}

void ARC_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;

	ARC_LLVM_printInst(MI, MI->address, "", O);
}

void ARC_setup_op(cs_arc_op *op)
{
	memset(op, 0, sizeof(cs_arc_op));
	op->type = ARC_OP_INVALID;
}

void ARC_init_cs_detail(MCInst *MI)
{
	if (!detail_is_set(MI)) {
		return;
	}
	unsigned int i;

	memset(get_detail(MI), 0, offsetof(cs_detail, arc) + sizeof(cs_arc));

	for (i = 0; i < ARR_SIZE(ARC_get_detail(MI)->operands); i++)
		ARC_setup_op(&ARC_get_detail(MI)->operands[i]);
}

static const map_insn_ops insn_operands[] = {
#include "ARCGenCSMappingInsnOp.inc"
};

void ARC_set_detail_op_imm(MCInst *MI, unsigned OpNum, arc_op_type ImmType,
			   int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	ARC_check_safe_inc(MI);
	CS_ASSERT((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
	CS_ASSERT(ImmType == ARC_OP_IMM);

	ARC_get_detail_op(MI, 0)->type = ImmType;
	ARC_get_detail_op(MI, 0)->imm = Imm;
	ARC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	ARC_inc_op_count(MI);
}

void ARC_set_detail_op_reg(MCInst *MI, unsigned OpNum, arc_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	ARC_check_safe_inc(MI);
	CS_ASSERT((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	ARC_get_detail_op(MI, 0)->type = ARC_OP_REG;
	ARC_get_detail_op(MI, 0)->reg = Reg;
	ARC_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	ARC_inc_op_count(MI);
}

void ARC_add_cs_detail(MCInst *MI, int op_group, va_list args)
{
	if (!detail_is_set(MI))
		return;

	unsigned OpNum = va_arg(args, unsigned);
	cs_op_type op_type = map_get_op_type(MI, OpNum);
	cs_op_type base_op_type = op_type;
	cs_op_type offset_op_type;
	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		CS_ASSERT_RET(0);
	case ARC_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum));
		} else if (op_type == CS_OP_REG) {
			ARC_set_detail_op_reg(MI, OpNum,
					      MCInst_getOpVal(MI, OpNum));
		} else {
			// Expression
			ARC_set_detail_op_imm(
				MI, OpNum, ARC_OP_IMM,
				MCOperand_getImm(MCInst_getOperand(MI, OpNum)));
		}
		break;
	case ARC_OP_GROUP_PredicateOperand:
		if (op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		break;
	case ARC_OP_GROUP_MemOperandRI:
		if (base_op_type == CS_OP_REG) {
			ARC_set_detail_op_reg(MI, OpNum,
					      MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		offset_op_type = map_get_op_type(MI, OpNum + 1);
		if (offset_op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum + 1, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum + 1));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		break;
	case ARC_OP_GROUP_BRCCPredicateOperand:
		if (op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		break;
	case ARC_OP_GROUP_CCOperand:
		if (op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		break;
	case ARC_OP_GROUP_U6:
		if (op_type == CS_OP_IMM) {
			ARC_set_detail_op_imm(MI, OpNum, ARC_OP_IMM,
					      MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT(0 && "Op type not handled.");
		break;
	}
}

#endif
