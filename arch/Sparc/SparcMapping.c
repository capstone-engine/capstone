/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SPARC

#include <stdio.h> // debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"

#include "SparcMapping.h"

void Sparc_init_cs_detail(MCInst *MI)
{
	if (!detail_is_set(MI)) {
		return;
	}
	memset(get_detail(MI), 0, offsetof(cs_detail, sparc) + sizeof(cs_sparc));
	Sparc_get_detail(MI)->cc = SPARC_CC_UNDEF;
	Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_NONE;
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
	const sparc_suppl_info *suppl_info =
		map_get_suppl_info(MI, sparc_insns);
	if (suppl_info) {
		Sparc_get_detail(MI)->format = suppl_info->form;
	}
}

/// Adds details which are not defined consistently as LLVM operands like
/// condition codes for alias instructions or branch hint bits.
static void Sparc_add_bit_details(MCInst *MI, const uint8_t *Bytes,
				  size_t BytesLen)
{
	if (!Bytes || BytesLen < 4 || !detail_is_set(MI)) {
		return;
	}
	uint32_t insn = readBytes32(MI, Bytes);

	// CC field
	cs_sparc *detail = Sparc_get_detail(MI);
	switch (detail->format) {
	default:
		break;
	case SPARC_INSN_FORM_F2_2: {
		// This format is used either by B or FB instructions.
		// The op2 == 6 for the FB and 2 for B.
		// This is the only indicator we have here to determine which CC field is used
		// if we don't want big switch cases.
		//
		// See: Opcode Maps - Table 39 - Sparc V9 ISA
		size_t op2 = get_insn_field_r(insn, 22, 24);
		detail->cc_field = op2 == 6 ? SPARC_CC_FIELD_FCC0 : SPARC_CC_FIELD_ICC;
		break;
	}
	case SPARC_INSN_FORM_F2_3:
		detail->cc_field = get_insn_field_r(insn, 20, 21);
		if (get_insn_field_r(insn, 22, 24) == 1) {
			// BPcc and FBPcc encode their fields in two bits.
			// BPcc needs the upper bit set to match our CC field enum.
			detail->cc_field |= 0x4;
		}
		break;
	case SPARC_INSN_FORM_TRAPSP:
		detail->cc_field = 0x4 | get_insn_field_r(insn, 11, 12);
		break;
	case SPARC_INSN_FORM_F4_1:
	case SPARC_INSN_FORM_F4_2:
		detail->cc_field = get_insn_field_r(insn, 11, 12);
		detail->cc_field |= get_insn_field_r(insn, 18, 18) << 2;
		break;
	case SPARC_INSN_FORM_F4_3:
		detail->cc_field = get_insn_field_r(insn, 11, 13);
		break;
	}

	// Condition codes
	switch (detail->format) {
	default:
		break;
	case SPARC_INSN_FORM_F2_1:
	case SPARC_INSN_FORM_F2_2:
	case SPARC_INSN_FORM_F2_3:
	case SPARC_INSN_FORM_TRAPSP: {
		// cond
		// Alias instructions don't define the conditions as operands.
		// We need to add them here to the details again.
		sparc_cc cc = get_insn_field_r(insn, 25, 28);
		if (MCInst_getOpcode(MI) == Sparc_CBCOND ||
		    MCInst_getOpcode(MI) == Sparc_CBCONDA) {
			cc += SPARC_CC_CPCC_BEGIN;
		}
		detail->cc = cc;
		break;
	}
	case SPARC_INSN_FORM_F4_1:
	case SPARC_INSN_FORM_F4_2:
	case SPARC_INSN_FORM_F4_3: {
		sparc_cc cc = get_insn_field_r(insn, 14, 17);
		detail->cc = cc;
		break;
	}
	case SPARC_INSN_FORM_F2_4: {
		// cond
		// Alias instructions don't define the conditions as operands.
		// We need to add them here to the details again.
		sparc_cc rcc = get_insn_field_r(insn, 25, 27);
		detail->cc = rcc + SPARC_CC_REG_BEGIN;
		break;
	}
	case SPARC_INSN_FORM_F4_4R:
	case SPARC_INSN_FORM_F4_4I: {
		sparc_cc rcc = get_insn_field_r(insn, 10, 12);
		detail->cc = rcc + SPARC_CC_REG_BEGIN;
		break;
	}
	}
	switch (detail->cc_field) {
	default:
	case SPARC_CC_FIELD_ICC:
	case SPARC_CC_FIELD_XCC:
		break;
	case SPARC_CC_FIELD_FCC0:
	case SPARC_CC_FIELD_FCC1:
	case SPARC_CC_FIELD_FCC2:
	case SPARC_CC_FIELD_FCC3:
		detail->cc += SPARC_CC_FCC_BEGIN;
		break;
	}

	// Hints
	switch (detail->format) {
	default:
		break;
	case SPARC_INSN_FORM_F2_2:
		detail->hint = get_insn_field_r(insn, 29, 29);
		break;
	case SPARC_INSN_FORM_F2_3:
	case SPARC_INSN_FORM_F2_4:
		detail->hint = get_insn_field_r(insn, 29, 29);
		detail->hint |=
			get_insn_field_r(insn, 19, 19) == 0 ? SPARC_HINT_PN :
							      SPARC_HINT_PT;
		break;
	}
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

	Sparc_add_bit_details(instr, code, code_len);
	return Result;
}

void Sparc_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, SparcRegDesc, sizeof(SparcRegDesc), 0, 0,
		SparcMCRegisterClasses, ARR_SIZE(SparcMCRegisterClasses), 0, 0,
		SparcRegDiffLists, 0, SparcSubRegIdxLists,
		ARR_SIZE(SparcSubRegIdxLists), 0);
}

const char *Sparc_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;

	if (syntax_opt & CS_OPT_SYNTAX_NOREGNAME) {
		return Sparc_LLVM_getRegisterName(reg, Sparc_NoRegAltName);
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
	{ SPARC_INS_ALIAS_CALL, "call" },
	{ SPARC_INS_ALIAS_END, NULL },
};
#endif

static void insert_op(MCInst *MI, unsigned index, cs_sparc_op op)
{
	if (!detail_is_set(MI)) {
		return;
	}
	Sparc_check_safe_inc(MI);

	cs_sparc_op *ops = Sparc_get_detail(MI)->operands;
	int i = Sparc_get_detail(MI)->op_count;
	if (index == -1) {
		ops[i] = op;
		Sparc_inc_op_count(MI);
		return;
	}
	for (; i > 0 && i > index; --i) {
		ops[i] = ops[i - 1];
	}
	ops[index] = op;
	Sparc_inc_op_count(MI);
}

/// Inserts a register to the detail operands at @index.
/// Already present operands are moved.
/// If @index is -1 the operand is appended.
static void Sparc_insert_detail_op_reg_at(MCInst *MI, unsigned index, sparc_reg Reg,
				 cs_ac_type access)
{
	if (!detail_is_set(MI))
		return;

	cs_sparc_op op = { 0 };
	op.type = SPARC_OP_REG;
	op.reg = Reg;
	op.access = access;
	insert_op(MI, index, op);
}

static void Sparc_correct_details(MCInst *MI)
{
	if (!detail_is_set(MI)) {
		return;
	}
	switch (MCInst_getOpcode(MI)) {
	default:
		return;
	case Sparc_LDSTUBri:
	case Sparc_LDSTUBrr:
	case Sparc_LDSTUBAri:
	case Sparc_LDSTUBArr:
		// The memory gets written back with ones
		// but there is not write back memory operand defined
		// (if even possible).
		Sparc_get_detail(MI)->operands[0].access = CS_AC_READ_WRITE;
		break;
	case Sparc_RDPSR:
		Sparc_insert_detail_op_reg_at(MI, 0, SPARC_REG_PSR, CS_AC_READ);
		break;
	case Sparc_PWRPSRri:
	case Sparc_PWRPSRrr:
	case Sparc_WRPSRri:
	case Sparc_WRPSRrr:
		Sparc_insert_detail_op_reg_at(MI, -1, SPARC_REG_PSR, CS_AC_WRITE);
		break;
	case Sparc_RDWIM:
		Sparc_insert_detail_op_reg_at(MI, 0, SPARC_REG_WIM, CS_AC_READ);
		break;
	case Sparc_WRWIMri:
	case Sparc_WRWIMrr:
		Sparc_insert_detail_op_reg_at(MI, -1, SPARC_REG_WIM, CS_AC_WRITE);
		break;
	case Sparc_RDTBR:
		Sparc_insert_detail_op_reg_at(MI, 0, SPARC_REG_TBR, CS_AC_READ);
		break;
	case Sparc_WRTBRri:
	case Sparc_WRTBRrr:
		Sparc_insert_detail_op_reg_at(MI, -1, SPARC_REG_TBR, CS_AC_WRITE);
		break;
	}
}

void Sparc_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;
	MI->flat_insn->usesAliasDetails = map_use_alias_details(MI);
	Sparc_LLVM_printInst(MI, MI->address, "", O);

#ifndef CAPSTONE_DIET
	map_set_alias_id(MI, O, insn_alias_mnem_map,
			 ARR_SIZE(insn_alias_mnem_map));
	Sparc_correct_details(MI);
#endif
}

const char *Sparc_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < SPARC_INS_ALIAS_END && id > SPARC_INS_ALIAS_BEGIN) {
		if (id - SPARC_INS_ALIAS_BEGIN >= ARR_SIZE(insn_alias_mnem_map))
			return NULL;

		return insn_alias_mnem_map[id - SPARC_INS_ALIAS_BEGIN - 1].name;
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

void Sparc_set_detail_op_imm(MCInst *MI, unsigned OpNum, sparc_op_type ImmType,
			     int64_t Imm)
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

	switch (Reg) {
	default:
		Sparc_get_detail_op(MI, 0)->type = SPARC_OP_REG;
		Sparc_get_detail_op(MI, 0)->reg = Reg;
		Sparc_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		Sparc_inc_op_count(MI);
		return;
	// The LLVM definition is inconsistent with the cc fields.
	// Sometimes they are encoded as register, sometimes not at all.
	// For Capstone they are always saved in the cc_field field for now.
	case SPARC_REG_ICC:
		Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_ICC;
		break;
	case SPARC_REG_FCC0:
		Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_FCC0;
		break;
	case SPARC_REG_FCC1:
		Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_FCC1;
		break;
	case SPARC_REG_FCC2:
		Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_FCC2;
		break;
	case SPARC_REG_FCC3:
		Sparc_get_detail(MI)->cc_field = SPARC_CC_FIELD_FCC3;
		break;
	}
}

static inline bool is_single_reg_mem_case(MCInst *MI, unsigned OpNo)
{
	if (map_get_op_type(MI, OpNo) != CS_OP_MEM_REG) {
		return false;
	}
	cs_sparc_op *prev_op = Sparc_get_detail_op(MI, -1);
	if (prev_op && prev_op->type == SPARC_OP_MEM) {
		return false;
	}
	if (MI->size == 1) {
		return true;
	} else if (MI->size > OpNo + 1 && Sparc_get_detail(MI)->operands[0].type != SPARC_OP_MEM) {
		// Next operand is not a memory operand (disponent or index reg).
		return !(map_get_op_type(MI, OpNo + 1) & SPARC_OP_MEM);
	}
	return false;
}

void Sparc_add_cs_detail_0(MCInst *MI, sparc_op_group op_group, unsigned OpNo)
{
	if (!detail_is_set(MI) || !map_fill_detail_ops(MI))
		return;

	cs_op_type op_type = map_get_op_type(MI, OpNo);

	switch (op_group) {
	default:
	case Sparc_OP_GROUP_GetPCX:
		printf("Operand group %d not handled!\n", op_group);
		return;
	case Sparc_OP_GROUP_Operand:
		if (op_type & CS_OP_MEM) {
			if (is_single_reg_mem_case(MI, OpNo)) {
				Sparc_get_detail_op(MI, 0)->type = SPARC_OP_MEM;
				Sparc_get_detail_op(MI, 0)->mem.base =
					MCInst_getOpVal(MI, OpNo);
				Sparc_get_detail_op(MI, 0)->access =
					map_get_op_access(MI, OpNo);
				Sparc_inc_op_count(MI);
			}
			break;
		}
		if (op_type == CS_OP_IMM) {
			Sparc_set_detail_op_imm(MI, OpNo, SPARC_OP_IMM,
						MCInst_getOpVal(MI, OpNo));
		} else if (op_type == CS_OP_REG) {
			Sparc_set_detail_op_reg(MI, OpNo,
						MCInst_getOpVal(MI, OpNo));
		} else {
			CS_ASSERT_RET(0 && "Op type not handled.");
		}
		Sparc_get_detail_op(MI, 0)->access =
			map_get_op_access(MI, OpNo);
		break;
	case Sparc_OP_GROUP_CCOperand: {
		// Handled in Sparc_add_bit_details().
		break;
	}
	case Sparc_OP_GROUP_MemOperand: {
		cs_sparc_op *prev_op = Sparc_get_detail_op(MI, -1);
		if (prev_op && prev_op->type == SPARC_OP_MEM) {
			// Already added.
			break;
		}
		MCOperand *Op1 = MCInst_getOperand(MI, (OpNo));
		MCOperand *Op2 = MCInst_getOperand(MI, (OpNo + 1));
		if (!MCOperand_isReg(Op1) ||
		    MCOperand_getReg(Op1) == Sparc_G0) {
			// Ignored
			return;
		}
		Sparc_get_detail_op(MI, 0)->type = SPARC_OP_MEM;
		Sparc_get_detail_op(MI, 0)->access =
			map_get_op_access(MI, OpNo);
		Sparc_get_detail_op(MI, 0)->mem.base = MCOperand_getReg(Op1);

		if (MCOperand_isReg(Op2) && MCOperand_getReg(Op2) != Sparc_G0) {
			Sparc_get_detail_op(MI, 0)->mem.index =
				MCOperand_getReg(Op2);
		} else if (MCOperand_isImm(Op2) && MCOperand_getImm(Op2) != 0) {
			Sparc_get_detail_op(MI, 0)->mem.disp =
				MCOperand_getImm(Op2);
		}
		Sparc_inc_op_count(MI);
		break;
	}
	case Sparc_OP_GROUP_ASITag:
		Sparc_get_detail_op(MI, 0)->type = SPARC_OP_ASI;
		Sparc_get_detail_op(MI, 0)->access =
			map_get_op_access(MI, OpNo);
		Sparc_get_detail_op(MI, 0)->asi =
			MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		Sparc_inc_op_count(MI);
		break;
	case Sparc_OP_GROUP_MembarTag:
		Sparc_get_detail_op(MI, 0)->type = SPARC_OP_MEMBAR_TAG;
		Sparc_get_detail_op(MI, 0)->access =
			map_get_op_access(MI, OpNo);
		Sparc_get_detail_op(MI, 0)->membar_tag =
			MCOperand_getImm(MCInst_getOperand(MI, OpNo));
		Sparc_inc_op_count(MI);
		break;
	}
}

#endif
