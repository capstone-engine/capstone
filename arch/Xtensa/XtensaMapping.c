/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#include <capstone/xtensa.h>

#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"
#include "XtensaDisassembler.h"
#include "XtensaInstPrinter.h"
#include "priv.h"
#include "XtensaMapping.h"

#ifndef CAPSTONE_DIET

static const char *const insn_name_maps[] = {
#include "XtensaGenCSMappingInsnName.inc"
};

static const name_map group_name_maps[] = {
#include "XtensaGenCSFeatureName.inc"
};

static const insn_map mapping_insns[] = {
#include "XtensaGenCSMappingInsn.inc"
};

static const map_insn_ops insn_operands[] = {
#include "XtensaGenCSMappingInsnOp.inc"
};

#endif

#define GET_REGINFO_MC_DESC
#include "XtensaGenRegisterInfo.inc"
#include "../../MathExtras.h"

void Xtensa_init_mri(MCRegisterInfo *mri)
{
	MCRegisterInfo_InitMCRegisterInfo(
		mri, XtensaRegDesc, ARR_SIZE(XtensaRegDesc), 0, 0,
		XtensaMCRegisterClasses, ARR_SIZE(XtensaMCRegisterClasses), 0,
		0, XtensaRegDiffLists, NULL, XtensaSubRegIdxLists,
		ARR_SIZE(XtensaSubRegIdxLists), XtensaRegEncodingTable);
}

void Xtensa_printer(MCInst *MI, SStream *OS, void *info)
{
	Xtensa_LLVM_printInstruction(MI, MI->address, OS);
}

static void set_instr_map_data(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	map_cs_id(MI, mapping_insns, ARR_SIZE(mapping_insns));
	map_implicit_reads(MI, mapping_insns);
	map_implicit_writes(MI, mapping_insns);
	map_groups(MI, mapping_insns);

	const xtensa_suppl_info *suppl_info =
		map_get_suppl_info(MI, mapping_insns);
	if (suppl_info) {
		Xtensa_get_detail(MI)->format = suppl_info->form;
	}
#endif
}

bool Xtensa_disasm(csh handle, const uint8_t *code, size_t code_len,
		   MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	DecodeStatus res = Xtensa_LLVM_getInstruction(instr, size, code,
						      code_len, address);
	if (res != MCDisassembler_Fail) {
		set_instr_map_data(instr);
	}
	if (res == MCDisassembler_SoftFail) {
		MCInst_setSoftFail(instr);
	}
	return res != MCDisassembler_Fail;
}

const char *Xtensa_reg_name(csh handle, unsigned int id)
{
	return Xtensa_LLVM_getRegisterName(id);
}

void Xtensa_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Done in Xtensa_disasm
}

const char *Xtensa_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ARR_SIZE(insn_name_maps)) {
		return NULL;
	}
	return insn_name_maps[id];
#else
	return NULL;
#endif
}

const char *Xtensa_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
void Xtensa_reg_access(const cs_insn *insn, cs_regs regs_read,
		       uint8_t *regs_read_count, cs_regs regs_write,
		       uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_xtensa *detail = &(insn->detail->xtensa);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < detail->op_count; i++) {
		cs_xtensa_op *op = &(detail->operands[i]);
		switch (op->type) {
		case XTENSA_OP_REG:
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
		case XTENSA_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.base != XTENSA_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = (uint16_t)op->mem.base;
				read_count++;
			}
			if ((insn->detail->writeback) &&
			    (op->mem.base != XTENSA_REG_INVALID) &&
			    !arr_exist(regs_write, write_count, op->mem.base)) {
				regs_write[write_count] =
					(uint16_t)op->mem.base;
				write_count++;
			}
		default:
			break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

int64_t Xtensa_L32R_Value(MCInst *MI, int op_num)
{
	int64_t InstrOff = MCOperand_getImm(MCInst_getOperand(MI, (op_num)));
	CS_ASSERT((InstrOff >= -262144 && InstrOff <= -4) &&
		  "Invalid argument, value must be in ranges [-262144,-4]");
	int64_t Value = 0;
	if (MI->csh->LITBASE & 0x1) {
		Value = (MI->csh->LITBASE & 0xfffff000) + InstrOff;
	} else {
		Value = (((int64_t)MI->address + 3) & ~0x3) + InstrOff;
	}
	return Value;
}

void Xtensa_add_cs_detail_0(MCInst *MI, xtensa_op_group op_group, int op_num)
{
	if (!detail_is_set(MI)) {
		return;
	}

	cs_xtensa_op *xop = Xtensa_get_detail_op(MI, 0);
	if (!xop) {
		return;
	}

	switch (op_group) {
	case Xtensa_OP_GROUP_Operand: {
		const MCOperand *MC = MCInst_getOperand(MI, op_num);
		if (MCOperand_isReg(MC)) {
			xop->type = XTENSA_OP_REG;
			xop->reg = MC->RegVal;
		} else if (MCOperand_isImm(MC)) {
			xop->type = XTENSA_OP_IMM;
			xop->imm = MC->ImmVal;
		}
	} break;
	case Xtensa_OP_GROUP_Imm1_16_AsmOperand:
	case Xtensa_OP_GROUP_Imm1n_15_AsmOperand:
	case Xtensa_OP_GROUP_Imm7_22_AsmOperand:
	case Xtensa_OP_GROUP_Imm8_AsmOperand:
	case Xtensa_OP_GROUP_Imm8_sh8_AsmOperand:
	case Xtensa_OP_GROUP_Imm8n_7_AsmOperand:
	case Xtensa_OP_GROUP_Imm12_AsmOperand:
	case Xtensa_OP_GROUP_Imm12m_AsmOperand:
	case Xtensa_OP_GROUP_Imm32n_95_AsmOperand:
	case Xtensa_OP_GROUP_Imm64n_4n_AsmOperand:
	case Xtensa_OP_GROUP_ImmOperand_minus32_28_4:
	case Xtensa_OP_GROUP_Uimm5_AsmOperand:
	case Xtensa_OP_GROUP_Uimm4_AsmOperand:
	case Xtensa_OP_GROUP_Shimm0_31_AsmOperand:
	case Xtensa_OP_GROUP_Shimm1_31_AsmOperand:
	case Xtensa_OP_GROUP_B4const_AsmOperand:
	case Xtensa_OP_GROUP_B4constu_AsmOperand:
	case Xtensa_OP_GROUP_ImmOperand_minus16_14_2:
	case Xtensa_OP_GROUP_ImmOperand_minus64_56_8:
	case Xtensa_OP_GROUP_ImmOperand_0_56_8:
	case Xtensa_OP_GROUP_ImmOperand_minus16_47_1:
	case Xtensa_OP_GROUP_ImmOperand_0_3_1:
	case Xtensa_OP_GROUP_ImmOperand_0_63_1:
	case Xtensa_OP_GROUP_Entry_Imm12_AsmOperand:
	case Xtensa_OP_GROUP_Offset8m32_AsmOperand:
	case Xtensa_OP_GROUP_Select_4_AsmOperand:
	case Xtensa_OP_GROUP_Select_2_AsmOperand:
	case Xtensa_OP_GROUP_Select_8_AsmOperand:
	case Xtensa_OP_GROUP_Offset_16_16_AsmOperand:
	case Xtensa_OP_GROUP_Offset_256_8_AsmOperand:
	case Xtensa_OP_GROUP_Offset_256_16_AsmOperand:
	case Xtensa_OP_GROUP_Offset_256_4_AsmOperand:
	case Xtensa_OP_GROUP_Select_16_AsmOperand:
	case Xtensa_OP_GROUP_Offset_128_2_AsmOperand:
	case Xtensa_OP_GROUP_Offset_128_1_AsmOperand:
	case Xtensa_OP_GROUP_Offset_64_16_AsmOperand:
	case Xtensa_OP_GROUP_Select_256_AsmOperand: {
		int64_t val = MCOperand_getImm(MCInst_getOperand(MI, op_num));
		xop->type = XTENSA_OP_IMM;
		xop->imm = (int32_t)val;
	} break;
	case Xtensa_OP_GROUP_BranchTarget:
	case Xtensa_OP_GROUP_JumpTarget:
	case Xtensa_OP_GROUP_CallOperand:
	case Xtensa_OP_GROUP_LoopTarget: {
		int64_t val =
			MCOperand_getImm(MCInst_getOperand(MI, op_num)) + 4;
		xop->type = XTENSA_OP_IMM;
		xop->imm = (int32_t)val;
	} break;
	case Xtensa_OP_GROUP_L32RTarget: {
		xop->type = XTENSA_OP_L32R;
		xop->imm = (int32_t)Xtensa_L32R_Value(MI, op_num);
	} break;
	case Xtensa_OP_GROUP_MemOperand: {
		unsigned reg =
			MCOperand_getReg(MCInst_getOperand(MI, (op_num)));
		int64_t imm8 =
			MCOperand_getImm(MCInst_getOperand(MI, op_num + 1));
		xop->type = XTENSA_OP_MEM;
		xop->mem.base = reg;
		xop->mem.disp = (int32_t)imm8;
	} break;
	}

	xop->access = map_get_op_access(MI, op_num);
	Xtensa_inc_op_count(MI);
}
