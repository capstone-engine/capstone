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

#ifndef CAPSTONE_DIET
static const name_map insn_alias_mnem_map[] = {
#include "LoongArchGenCSAliasMnemMap.inc"
	{ LOONGARCH_INS_ALIAS_END, NULL },
};
#endif

const char *LoongArch_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < LOONGARCH_INS_ALIAS_END && id > LOONGARCH_INS_ALIAS_BEGIN) {
		if (id - LOONGARCH_INS_ALIAS_BEGIN >=
		    ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - LOONGARCH_INS_ALIAS_BEGIN - 1]
			.name;
	}
	if (id >= LOONGARCH_INS_ENDING)
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
	{ LOONGARCH_GRP_INVALID, NULL },

	{ LOONGARCH_GRP_JUMP, "jump" },
	{ LOONGARCH_GRP_CALL, "call" },
	{ LOONGARCH_GRP_RET, "return" },
	{ LOONGARCH_GRP_INT, "int" },
	{ LOONGARCH_GRP_IRET, "iret" },
	{ LOONGARCH_GRP_PRIVILEGE, "privilege" },
	{ LOONGARCH_GRP_BRANCH_RELATIVE, "branch_relative" },

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
		case LOONGARCH_OP_REG:
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
		case LOONGARCH_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.base != LOONGARCH_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = (uint16_t)op->mem.base;
				read_count++;
			}
			if ((insn->detail->writeback) &&
			    (op->mem.base != LOONGARCH_REG_INVALID) &&
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
	if (!suppl_info)
		return;

	if (suppl_info->memory_access == CS_AC_INVALID) {
		// not memory instruction
		return;
	}

	// handle special cases
	unsigned int base;
	switch (MI->flat_insn->id) {
	case LOONGARCH_INS_SC_Q:
	case LOONGARCH_INS_LLACQ_W:
	case LOONGARCH_INS_LLACQ_D:
	case LOONGARCH_INS_SCREL_W:
	case LOONGARCH_INS_SCREL_D:
		// last register rj is memory operand
		LoongArch_get_detail_op(MI, -1)->type = LOONGARCH_OP_MEM;
		base = LoongArch_get_detail_op(MI, -1)->reg;
		LoongArch_get_detail_op(MI, -1)->mem.base = base;
		LoongArch_get_detail_op(MI, -1)->access =
			suppl_info->memory_access;
		return;

	case LOONGARCH_INS_LDGT_B:
	case LOONGARCH_INS_LDGT_H:
	case LOONGARCH_INS_LDGT_W:
	case LOONGARCH_INS_LDGT_D:
	case LOONGARCH_INS_LDLE_B:
	case LOONGARCH_INS_LDLE_H:
	case LOONGARCH_INS_LDLE_W:
	case LOONGARCH_INS_LDLE_D:
	case LOONGARCH_INS_STGT_B:
	case LOONGARCH_INS_STGT_H:
	case LOONGARCH_INS_STGT_W:
	case LOONGARCH_INS_STGT_D:
	case LOONGARCH_INS_STLE_B:
	case LOONGARCH_INS_STLE_H:
	case LOONGARCH_INS_STLE_W:
	case LOONGARCH_INS_STLE_D:
	case LOONGARCH_INS_FLDLE_S:
	case LOONGARCH_INS_FLDLE_D:
	case LOONGARCH_INS_FLDGT_S:
	case LOONGARCH_INS_FLDGT_D:
	case LOONGARCH_INS_FSTLE_S:
	case LOONGARCH_INS_FSTLE_D:
	case LOONGARCH_INS_FSTGT_S:
	case LOONGARCH_INS_FSTGT_D:
		// second register rj is memory operand
		LoongArch_get_detail_op(MI, -2)->type = LOONGARCH_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		return;
	default:
		break;
	}

	switch (suppl_info->form) {
	case LOONGARCH_INSN_FORM_FMT2RI12:	 // ld, ldl, ldr, st, stl, str
	case LOONGARCH_INSN_FORM_FMT2RI14:	 // ll, sc, ldptr, stptr
	case LOONGARCH_INSN_FORM_FMT2RI9_VRI:	 // vldrepl.d
	case LOONGARCH_INSN_FORM_FMT2RI10_VRI:	 // vldrepl.w
	case LOONGARCH_INSN_FORM_FMT2RI11_VRI:	 // vldrepl.h
	case LOONGARCH_INSN_FORM_FMT2RI12_VRI:	 // vld, vldrepl, vst
	case LOONGARCH_INSN_FORM_FMT2RI8I1_VRII: // vstelm.d
	case LOONGARCH_INSN_FORM_FMT2RI8I2_VRII: // vstelm.w
	case LOONGARCH_INSN_FORM_FMT2RI8I3_VRII: // vstelm.h
	case LOONGARCH_INSN_FORM_FMT2RI8I4_VRII: // vstelm.b
	case LOONGARCH_INSN_FORM_FMT2RI9_XRI:	 // xvldrepl.d
	case LOONGARCH_INSN_FORM_FMT2RI10_XRI:	 // xvldrepl.w
	case LOONGARCH_INSN_FORM_FMT2RI11_XRI:	 // xvldrepl.h
	case LOONGARCH_INSN_FORM_FMT2RI12_XRI:	 // xvld, xvldrepl, xvst
	case LOONGARCH_INSN_FORM_FMT2RI8I2_XRII: // xvstelm.d
	case LOONGARCH_INSN_FORM_FMT2RI8I3_XRII: // xvstelm.w
	case LOONGARCH_INSN_FORM_FMT2RI8I4_XRII: // xvstelm.h
	case LOONGARCH_INSN_FORM_FMT2RI8I5_XRII: // xvstelm.b
	case LOONGARCH_INSN_FORM_FMTPRELD:	 // preld
	case LOONGARCH_INSN_FORM_FPFMT2RI12:	 // fld, fst
		// immediate offset
		LoongArch_get_detail_op(MI, -2)->type = LOONGARCH_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->mem.disp =
			LoongArch_get_detail_op(MI, -1)->imm;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		LoongArch_dec_op_count(MI);
		break;

	case LOONGARCH_INSN_FORM_FMT3R: // ldx, stx, amo
		if (suppl_info->memory_access == CS_AC_READ_WRITE) {
			// amo: read + write
			// last register rj is memory operand
			LoongArch_get_detail_op(MI, -1)->type =
				LOONGARCH_OP_MEM;
			base = LoongArch_get_detail_op(MI, -1)->reg;
			LoongArch_get_detail_op(MI, -1)->mem.base = base;
			LoongArch_get_detail_op(MI, -1)->access =
				suppl_info->memory_access;
			break;
		}
		// fallthrough

	case LOONGARCH_INSN_FORM_FPFMTMEM:  // fldx, fstx
	case LOONGARCH_INSN_FORM_FMT3R_VRR: // vldx, vstx
	case LOONGARCH_INSN_FORM_FMT3R_XRR: // xvldx, xvstx
	case LOONGARCH_INSN_FORM_FMTPRELDX: // preldx
		// register offset
		LoongArch_get_detail_op(MI, -2)->type = LOONGARCH_OP_MEM;
		base = LoongArch_get_detail_op(MI, -2)->reg;
		LoongArch_get_detail_op(MI, -2)->mem.base = base;
		LoongArch_get_detail_op(MI, -2)->mem.index =
			LoongArch_get_detail_op(MI, -1)->reg;
		LoongArch_get_detail_op(MI, -2)->access =
			suppl_info->memory_access;
		LoongArch_dec_op_count(MI);
		break;

	default:
		CS_ASSERT_RET(0 && "Unknown LoongArch memory instruction");
		break;
	}
}

void LoongArch_rewrite_address_operand(MCInst *MI)
{
	// rewrite offset immediate operand to absolute address in direct branch instructions
	// convert e.g.
	// 0x1000: beqz	$t0, 0x100c
	// op_count: 2
	//         operands[0].type: REG = t0
	//         operands[0].access: READ
	//         operands[1].type: IMM = 0xc
	//         operands[1].access: READ
	// to:
	// op_count: 2
	//         operands[0].type: REG = t0
	//         operands[0].access: READ
	//         operands[1].type: IMM = 0x100c
	//         operands[1].access: READ

	if (!detail_is_set(MI))
		return;

	// handle different types of branch instructions
	switch (MI->flat_insn->id) {
	case LOONGARCH_INS_B:
	case LOONGARCH_INS_BCEQZ:
	case LOONGARCH_INS_BCNEZ:
	case LOONGARCH_INS_BEQ:
	case LOONGARCH_INS_BEQZ:
	case LOONGARCH_INS_BGE:
	case LOONGARCH_INS_BGEU:
	case LOONGARCH_INS_BL:
	case LOONGARCH_INS_BLT:
	case LOONGARCH_INS_BLTU:
	case LOONGARCH_INS_BNE:
	case LOONGARCH_INS_BNEZ:
		// last operand is address operand
		LoongArch_get_detail_op(MI, -1)->imm += MI->address;
		return;

	default:
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
	DecodeStatus Result = LoongArch_LLVM_getInstruction(instr, &temp_size, code,
						    code_len, address, info);
	LoongArch_set_instr_map_data(instr);
	*size = temp_size;
	if (Result == MCDisassembler_SoftFail) {
		MCInst_setSoftFail(instr);
	}
	return Result != MCDisassembler_Fail;
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
	case LOONGARCH_INS_BL:
		add_group(MI, LOONGARCH_GRP_CALL);
		break;
	case LOONGARCH_INS_JIRL:
		if (loongarch->op_count == 3 &&
		    loongarch->operands[0].reg == LOONGARCH_REG_RA) {
			// call: jirl ra, rj, offs16
			add_group(MI, LOONGARCH_GRP_CALL);
		} else if (loongarch->op_count == 0) {
			// ret
			add_group(MI, LOONGARCH_GRP_RET);
		} else if (loongarch->op_count == 1) {
			// jr rj
			add_group(MI, LOONGARCH_GRP_JUMP);
		} else if (loongarch->op_count == 3) {
			// none of the above, generic jirl
			add_group(MI, LOONGARCH_GRP_JUMP);
		}
		break;
	case LOONGARCH_INS_B:
	case LOONGARCH_INS_BCEQZ:
	case LOONGARCH_INS_BEQ:
	case LOONGARCH_INS_BEQZ:
	case LOONGARCH_INS_BGE:
	case LOONGARCH_INS_BGEU:
	case LOONGARCH_INS_BLT:
	case LOONGARCH_INS_BLTU:
	case LOONGARCH_INS_BNE:
	case LOONGARCH_INS_BNEZ:
		add_group(MI, LOONGARCH_GRP_JUMP);
		add_group(MI, LOONGARCH_GRP_BRANCH_RELATIVE);
		break;
	case LOONGARCH_INS_SYSCALL:
		add_group(MI, LOONGARCH_GRP_INT);
		break;
	case LOONGARCH_INS_ERTN:
		add_group(MI, LOONGARCH_GRP_IRET);
		add_group(MI, LOONGARCH_GRP_PRIVILEGE);
		break;
	case LOONGARCH_INS_CSRXCHG:
	case LOONGARCH_INS_CACOP:
	case LOONGARCH_INS_LDDIR:
	case LOONGARCH_INS_LDPTE:
	case LOONGARCH_INS_IOCSRRD_B:
	case LOONGARCH_INS_IOCSRRD_H:
	case LOONGARCH_INS_IOCSRRD_W:
	case LOONGARCH_INS_IOCSRRD_D:
	case LOONGARCH_INS_IOCSRWR_B:
	case LOONGARCH_INS_IOCSRWR_H:
	case LOONGARCH_INS_IOCSRWR_W:
	case LOONGARCH_INS_IOCSRWR_D:
	case LOONGARCH_INS_TLBCLR:
	case LOONGARCH_INS_TLBFLUSH:
	case LOONGARCH_INS_TLBSRCH:
	case LOONGARCH_INS_TLBRD:
	case LOONGARCH_INS_TLBWR:
	case LOONGARCH_INS_INVTLB:
		add_group(MI, LOONGARCH_GRP_PRIVILEGE);
		break;
	}
}

void LoongArch_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	LoongArch_LLVM_printInst(MI, MI->address, "", O);

	LoongArch_rewrite_memory_operand(MI);
	LoongArch_rewrite_address_operand(MI);
	LoongArch_add_cs_groups(MI);
#ifndef CAPSTONE_DIET
	map_set_alias_id(MI, O, insn_alias_mnem_map,
			 ARR_SIZE(insn_alias_mnem_map));
#endif
}

void LoongArch_setup_op(cs_loongarch_op *op)
{
	memset(op, 0, sizeof(cs_loongarch_op));
	op->type = LOONGARCH_OP_INVALID;
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
	CS_ASSERT_RET((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
	CS_ASSERT_RET(ImmType == LOONGARCH_OP_IMM);

	LoongArch_get_detail_op(MI, 0)->type = ImmType;
	LoongArch_get_detail_op(MI, 0)->imm = Imm;
	LoongArch_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	LoongArch_inc_op_count(MI);
}

void LoongArch_set_detail_op_reg(MCInst *MI, unsigned OpNum, loongarch_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	CS_ASSERT_RET((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	LoongArch_get_detail_op(MI, 0)->type = LOONGARCH_OP_REG;
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
		CS_ASSERT_RET(0);
	case LoongArch_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			LoongArch_set_detail_op_imm(MI, OpNum, LOONGARCH_OP_IMM,
						    MCInst_getOpVal(MI, OpNum));
		} else if (op_type == CS_OP_REG) {
			LoongArch_set_detail_op_reg(MI, OpNum,
						    MCInst_getOpVal(MI, OpNum));
		} else
			CS_ASSERT_RET(0 && "Op type not handled.");
		break;
	case LoongArch_OP_GROUP_AtomicMemOp:
		CS_ASSERT_RET(op_type == CS_OP_REG);
		// converted to MEM operand later in LoongArch_rewrite_memory_operand
		LoongArch_set_detail_op_reg(MI, OpNum,
					    MCInst_getOpVal(MI, OpNum));
		break;
	}
}

#endif
