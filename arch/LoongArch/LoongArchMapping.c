/* Capstone Disassembly Engine */
/* By Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifdef CAPSTONE_HAS_LOONGARCH

#include <stdio.h>
#include <string.h>

#include <capstone/capstone.h>
#include <capstone/loongarch.h>

#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../cs_priv.h"
#include "../../cs_simple_types.h"

#include "LoongArchMapping.h"
#include "LoongArchLinkage.h"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "LoongArchGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "LoongArchGenInstrInfo.inc"

void LoongArch_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, LoongArchRegDesc,
					  sizeof(LoongArchRegDesc), 0, 0,
					  LoongArchMCRegisterClasses,
					  ARR_SIZE(LoongArchMCRegisterClasses),
					  0, 0, LoongArchRegDiffLists, 0,
					  LoongArchSubRegIdxLists,
					  ARR_SIZE(LoongArchSubRegIdxLists), 0);
}

const char *LoongArch_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;

	if (syntax_opt & CS_OPT_SYNTAX_NOREGNAME) {
		return LoongArch_LLVM_getRegisterName(reg,
						      LoongArch_NoRegAltName);
	}
	return LoongArch_LLVM_getRegisterName(reg, LoongArch_RegAliasName);
}

void LoongArch_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by LoongArch. Information is set after disassembly.
}

static const char *const insn_name_maps[] = {
#include "LoongArchGenCSMappingInsnName.inc"
};

const char *LoongArch_insn_name(csh handle, unsigned int id)
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
	{ LoongArch_GRP_INVALID, NULL },

	{ LoongArch_GRP_JUMP, "jump" },
	{ LoongArch_GRP_CALL, "call" },
	{ LoongArch_GRP_RET, "return" },
	{ LoongArch_GRP_INT, "int" },
	{ LoongArch_GRP_IRET, "iret" },
	{ LoongArch_GRP_PRIVILEGE, "privilege" },
	{ LoongArch_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture-specific groups
#include "LoongArchGenCSFeatureName.inc"
};
#endif

const char *LoongArch_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

void LoongArch_reg_access(const cs_insn *insn, cs_regs regs_read,
			  uint8_t *regs_read_count, cs_regs regs_write,
			  uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_loongarch *loongarch = &(insn->detail->loongarch);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < loongarch->op_count; i++) {
		cs_loongarch_op *op = &(loongarch->operands[i]);
		switch ((int)op->type) {
		case LoongArch_OP_REG:
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
		case LoongArch_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.base != LoongArch_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = (uint16_t)op->mem.base;
				read_count++;
			}
			if ((insn->detail->writeback) &&
			    (op->mem.base != LoongArch_REG_INVALID) &&
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

const insn_map loongarch_insns[] = {
#include "LoongArchGenCSMappingInsn.inc"
};

void LoongArch_rewrite_memory_operand(MCInst *MI)
{
	// rewrite base + disp operands to memory operands in memory instructions
	// convert e.g.
	// ld.d   $t3, $t2, 0x410
	// op_count: 3
	//         operands[0].type: REG = t3
	//         operands[0].access: WRITE
	//         operands[1].type: REG = t2
	//         operands[1].access: READ
	//         operands[2].type: IMM = 0x410
	//         operands[2].access: READ
	// to:
	// op_count: 3
	//         operands[0].type: REG = t3
	//         operands[0].access: WRITE
	//         operands[1].type: MEM
	//                 operands[1].mem.base: REG = t2
	//                 operands[1].mem.disp: 0x410
	//        operands[1].access: READ

	if (!detail_is_set(MI))
		return;

	const loongarch_suppl_info *suppl_info =
		map_get_suppl_info(MI, loongarch_insns);
	if (suppl_info->memory_access == CS_AC_INVALID) {
		// not memory instruction
		return;
	}

	// handle special cases
	unsigned int base;
	switch (MI->flat_insn->id) {
	case LoongArch_INS_SC_Q:
	case LoongArch_INS_LLACQ_W:
	case LoongArch_INS_LLACQ_D:
	case LoongArch_INS_SCREL_W:
	case LoongArch_INS_SCREL_D:
		// last register rj is memory operand
		LoongArch_get_detail_op(MI, -1)->type = LoongArch_OP_MEM;
		base = LoongArch_get_detail_op(MI, -1)->reg;
		LoongArch_get_detail_op(MI, -1)->mem.base = base;
		LoongArch_get_detail_op(MI, -1)->access =
			suppl_info->memory_access;
		return;

	case LoongArch_INS_LDGT_B:
	case LoongArch_INS_LDGT_H:
	case LoongArch_INS_LDGT_W:
	case LoongArch_INS_LDGT_D:
	case LoongArch_INS_LDLE_B:
	case LoongArch_INS_LDLE_H:
	case LoongArch_INS_LDLE_W:
	case LoongArch_INS_LDLE_D:
	case LoongArch_INS_STGT_B:
	case LoongArch_INS_STGT_H:
	case LoongArch_INS_STGT_W:
	case LoongArch_INS_STGT_D:
	case LoongArch_INS_STLE_B:
	case LoongArch_INS_STLE_H:
	case LoongArch_INS_STLE_W:
	case LoongArch_INS_STLE_D:
	case LoongArch_INS_FLDLE_S:
	case LoongArch_INS_FLDLE_D:
	case LoongArch_INS_FLDGT_S:
	case LoongArch_INS_FLDGT_D:
	case LoongArch_INS_FSTLE_S:
	case LoongArch_INS_FSTLE_D:
	case LoongArch_INS_FSTGT_S:
	case LoongArch_INS_FSTGT_D:
		// second register rj is memory operand
		LoongArch_get_detail_op(MI, -2)->type = LoongArch_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		return;
	default:
		break;
	}

	switch (suppl_info->form) {
	case LoongArch_INSN_FORM_FMT2RI12:	 // ld, ldl, ldr, st, stl, str
	case LoongArch_INSN_FORM_FMT2RI14:	 // ll, sc, ldptr, stptr
	case LoongArch_INSN_FORM_FMT2RI9_VRI:	 // vldrepl.d
	case LoongArch_INSN_FORM_FMT2RI10_VRI:	 // vldrepl.w
	case LoongArch_INSN_FORM_FMT2RI11_VRI:	 // vldrepl.h
	case LoongArch_INSN_FORM_FMT2RI12_VRI:	 // vld, vldrepl, vst
	case LoongArch_INSN_FORM_FMT2RI8I1_VRII: // vstelm.d
	case LoongArch_INSN_FORM_FMT2RI8I2_VRII: // vstelm.w
	case LoongArch_INSN_FORM_FMT2RI8I3_VRII: // vstelm.h
	case LoongArch_INSN_FORM_FMT2RI8I4_VRII: // vstelm.b
	case LoongArch_INSN_FORM_FMT2RI9_XRI:	 // xvldrepl.d
	case LoongArch_INSN_FORM_FMT2RI10_XRI:	 // xvldrepl.w
	case LoongArch_INSN_FORM_FMT2RI11_XRI:	 // xvldrepl.h
	case LoongArch_INSN_FORM_FMT2RI12_XRI:	 // xvld, xvldrepl, xvst
	case LoongArch_INSN_FORM_FMT2RI8I2_XRII: // xvstelm.d
	case LoongArch_INSN_FORM_FMT2RI8I3_XRII: // xvstelm.w
	case LoongArch_INSN_FORM_FMT2RI8I4_XRII: // xvstelm.h
	case LoongArch_INSN_FORM_FMT2RI8I5_XRII: // xvstelm.b
	case LoongArch_INSN_FORM_FMTPRELD:	 // preld
	case LoongArch_INSN_FORM_FPFMT2RI12:	 // fld, fst
		// immediate offset
		LoongArch_get_detail_op(MI, -2)->type = LoongArch_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->mem.disp =
			LoongArch_get_detail_op(MI, -1)->imm;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		LoongArch_dec_op_count(MI);
		break;

	case LoongArch_INSN_FORM_FMT3R: // ldx, stx, amo
		if (suppl_info->memory_access == CS_AC_READ_WRITE) {
			// amo: read + write
			// last register rj is memory operand
			LoongArch_get_detail_op(MI, -1)->type =
				LoongArch_OP_MEM;
			base = LoongArch_get_detail_op(MI, -1)->reg;
			LoongArch_get_detail_op(MI, -1)->mem.base = base;
			LoongArch_get_detail_op(MI, -1)->access =
				suppl_info->memory_access;
			break;
		}
		// fallthrough

	case LoongArch_INSN_FORM_FPFMTMEM:  // fldx, fstx
	case LoongArch_INSN_FORM_FMT3R_VRR: // vldx, vstx
	case LoongArch_INSN_FORM_FMT3R_XRR: // xvldx, xvstx
	case LoongArch_INSN_FORM_FMTPRELDX: // preldx
		// register offset
		LoongArch_get_detail_op(MI, -2)->type = LoongArch_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->mem.index =
			LoongArch_get_detail_op(MI, -1)->reg;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		LoongArch_dec_op_count(MI);
		break;

	default:
		assert(0 && "Unknown LoongArch memory instruction");
		break;
	}
}

void LoongArch_set_instr_map_data(MCInst *MI)
{
	map_cs_id(MI, loongarch_insns, ARR_SIZE(loongarch_insns));
	map_implicit_reads(MI, loongarch_insns);
	map_implicit_writes(MI, loongarch_insns);
	map_groups(MI, loongarch_insns);
	const loongarch_suppl_info *suppl_info =
		map_get_suppl_info(MI, loongarch_insns);
	if (suppl_info) {
		LoongArch_get_detail(MI)->format = suppl_info->form;
	}
}

bool LoongArch_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			      MCInst *instr, uint16_t *size, uint64_t address,
			      void *info)
{
	uint64_t temp_size;
	LoongArch_init_cs_detail(instr);
	bool Result = LoongArch_LLVM_getInstruction(instr, &temp_size, code,
						    code_len, address, info) !=
		      MCDisassembler_Fail;
	LoongArch_set_instr_map_data(instr);
	*size = temp_size;
	return Result;
}

/// Adds group to the instruction which are not defined in LLVM.
static void LoongArch_add_cs_groups(MCInst *MI)
{
	if (!MI->flat_insn->detail)
		return;
	unsigned Opcode = MI->flat_insn->id;
	cs_loongarch *loongarch = &(MI->flat_insn->detail->loongarch);
	switch (Opcode) {
	default:
		return;
	case LoongArch_INS_BL:
		add_group(MI, LoongArch_GRP_CALL);
		break;
	case LoongArch_INS_JIRL:
		if (loongarch->op_count == 3 &&
		    loongarch->operands[0].reg == LoongArch_REG_RA) {
			// call: jirl ra, rj, offs16
			add_group(MI, LoongArch_GRP_CALL);
		} else if (loongarch->op_count == 0) {
			// ret
			add_group(MI, LoongArch_GRP_RET);
		} else if (loongarch->op_count == 1) {
			// jr rj
			add_group(MI, LoongArch_GRP_JUMP);
		}
		break;
	case LoongArch_INS_B:
	case LoongArch_INS_BCEQZ:
	case LoongArch_INS_BEQ:
	case LoongArch_INS_BEQZ:
	case LoongArch_INS_BGE:
	case LoongArch_INS_BGEU:
	case LoongArch_INS_BLT:
	case LoongArch_INS_BLTU:
	case LoongArch_INS_BNE:
	case LoongArch_INS_BNEZ:
		add_group(MI, LoongArch_GRP_JUMP);
		add_group(MI, LoongArch_GRP_BRANCH_RELATIVE);
		break;
	case LoongArch_INS_SYSCALL:
		add_group(MI, LoongArch_GRP_INT);
		break;
	case LoongArch_INS_ERTN:
		add_group(MI, LoongArch_GRP_IRET);
		add_group(MI, LoongArch_GRP_PRIVILEGE);
		break;
	case LoongArch_INS_CSRXCHG:
	case LoongArch_INS_CACOP:
	case LoongArch_INS_LDDIR:
	case LoongArch_INS_LDPTE:
	case LoongArch_INS_IOCSRRD_B:
	case LoongArch_INS_IOCSRRD_H:
	case LoongArch_INS_IOCSRRD_W:
	case LoongArch_INS_IOCSRRD_D:
	case LoongArch_INS_IOCSRWR_B:
	case LoongArch_INS_IOCSRWR_H:
	case LoongArch_INS_IOCSRWR_W:
	case LoongArch_INS_IOCSRWR_D:
	case LoongArch_INS_TLBCLR:
	case LoongArch_INS_TLBFLUSH:
	case LoongArch_INS_TLBSRCH:
	case LoongArch_INS_TLBRD:
	case LoongArch_INS_TLBWR:
	case LoongArch_INS_INVTLB:
		add_group(MI, LoongArch_GRP_PRIVILEGE);
		break;
	}
}

void LoongArch_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;

	LoongArch_LLVM_printInst(MI, MI->address, "", O);

	LoongArch_rewrite_memory_operand(MI);
	LoongArch_add_cs_groups(MI);
}

void LoongArch_setup_op(cs_loongarch_op *op)
{
	memset(op, 0, sizeof(cs_loongarch_op));
	op->type = LoongArch_OP_INVALID;
}

void LoongArch_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		unsigned int i;

		memset(get_detail(MI), 0,
		       offsetof(cs_detail, loongarch) + sizeof(cs_loongarch));

		for (i = 0; i < ARR_SIZE(LoongArch_get_detail(MI)->operands);
		     i++)
			LoongArch_setup_op(
				&LoongArch_get_detail(MI)->operands[i]);
	}
}

static const map_insn_ops insn_operands[] = {
#include "LoongArchGenCSMappingInsnOp.inc"
};

void LoongArch_set_detail_op_imm(MCInst *MI, unsigned OpNum,
				 loongarch_op_type ImmType, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
	assert(ImmType == LoongArch_OP_IMM);

	LoongArch_get_detail_op(MI, 0)->type = ImmType;
	LoongArch_get_detail_op(MI, 0)->imm = Imm;
	LoongArch_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	LoongArch_inc_op_count(MI);
}

void LoongArch_set_detail_op_reg(MCInst *MI, unsigned OpNum, loongarch_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	LoongArch_get_detail_op(MI, 0)->type = LoongArch_OP_REG;
	LoongArch_get_detail_op(MI, 0)->reg = Reg;
	LoongArch_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	LoongArch_inc_op_count(MI);
}

void LoongArch_add_cs_detail(MCInst *MI, int /* loongarch_op_group */ op_group,
			     va_list args)
{
	if (!detail_is_set(MI))
		return;

	unsigned OpNum = va_arg(args, unsigned);
	// Handle memory operands later
	cs_op_type op_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case LoongArch_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			LoongArch_set_detail_op_imm(MI, OpNum, LoongArch_OP_IMM,
						    MCInst_getOpVal(MI, OpNum));
		} else if (op_type == CS_OP_REG) {
			LoongArch_set_detail_op_reg(MI, OpNum,
						    MCInst_getOpVal(MI, OpNum));
		} else
			assert(0 && "Op type not handled.");
		break;
	case LoongArch_OP_GROUP_AtomicMemOp:
		assert(op_type == CS_OP_REG);
		// converted to MEM operand later in LoongArch_rewrite_memory_operand
		LoongArch_set_detail_op_reg(MI, OpNum,
					    MCInst_getOpVal(MI, OpNum));
		break;
	}
}

#endif
