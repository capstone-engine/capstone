/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#include "BPFConstants.h"
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

	{ BPF_INS_ADD, "add" },
	{ BPF_INS_SUB, "sub" },
	{ BPF_INS_MUL, "mul" },
	{ BPF_INS_DIV, "div" },
	{ BPF_INS_OR, "or" },
	{ BPF_INS_AND, "and" },
	{ BPF_INS_LSH, "lsh" },
	{ BPF_INS_RSH, "rsh" },
	{ BPF_INS_NEG, "neg" },
	{ BPF_INS_MOD, "mod" },
	{ BPF_INS_XOR, "xor" },
	{ BPF_INS_MOV, "mov" },
	{ BPF_INS_ARSH, "arsh" },

	{ BPF_INS_ADD64, "add64" },
	{ BPF_INS_SUB64, "sub64" },
	{ BPF_INS_MUL64, "mul64" },
	{ BPF_INS_DIV64, "div64" },
	{ BPF_INS_OR64, "or64" },
	{ BPF_INS_AND64, "and64" },
	{ BPF_INS_LSH64, "lsh64" },
	{ BPF_INS_RSH64, "rsh64" },
	{ BPF_INS_NEG64, "neg64" },
	{ BPF_INS_MOD64, "mod64" },
	{ BPF_INS_XOR64, "xor64" },
	{ BPF_INS_MOV64, "mov64" },
	{ BPF_INS_ARSH64, "arsh64" },

	{ BPF_INS_LE16, "le16" },
	{ BPF_INS_LE32, "le32" },
	{ BPF_INS_LE64, "le64" },
	{ BPF_INS_BE16, "be16" },
	{ BPF_INS_BE32, "be32" },
	{ BPF_INS_BE64, "be64" },

	{ BPF_INS_LDABSB, "ldabsb" },

	{ BPF_INS_RET, "ret" },
	{ BPF_INS_TAX, "tax" },
	{ BPF_INS_TXA, "txa" },
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

static bpf_insn op2insn_ALU(unsigned opcode)
{
	/* Endian is a special case */
	if (BPF_OP(opcode) == BPF_ALU_END) {
		switch (opcode ^ BPF_CLASS_ALU ^ BPF_ALU_END) {
		case BPF_SRC_LITTLE | (16 << 4):
			return BPF_INS_LE16;
		case BPF_SRC_LITTLE | (32 << 4):
			return BPF_INS_LE32;
		case BPF_SRC_LITTLE | (64 << 4):
			return BPF_INS_LE64;
		case BPF_SRC_BIG | (16 << 4):
			return BPF_INS_BE16;
		case BPF_SRC_BIG | (32 << 4):
			return BPF_INS_BE32;
		case BPF_SRC_BIG | (64 << 4):
			return BPF_INS_BE64;
		}
		return BPF_INS_INVALID;
	}

#define CASE(c) case BPF_ALU_##c: \
		if (BPF_CLASS(opcode) == BPF_CLASS_ALU) \
			return BPF_INS_##c; \
		else \
			return BPF_INS_##c##64;

	switch (BPF_OP(opcode)) {
	CASE(ADD);
	CASE(SUB);
	CASE(MUL);
	CASE(DIV);
	CASE(OR);
	CASE(AND);
	CASE(LSH);
	CASE(RSH);
	CASE(NEG);
	CASE(MOD);
	CASE(XOR);
	CASE(MOV);
	CASE(ARSH);
	}
#undef CASE

	return BPF_INS_INVALID;
}

/*
 * 1. Convert opcode(id) to BPF_INS_*
 * 2. Set regs_read/regs_write/groups
 */
void BPF_get_insn_id(cs_struct *ud, cs_insn *insn, unsigned int opcode)
{
	// No need to care the mode (cBPF or eBPF) since all checks has be done in
	// BPF_getInstruction, we can simply map opcode to BPF_INS_*.
	cs_detail *detail;
	bpf_insn id = BPF_INS_INVALID;
	bpf_insn_group grp;

	detail = insn->detail;
#ifndef CAPSTONE_DIET
 #define PUSH_GROUP(grp) do { \
		if (detail) { \
			detail->groups[detail->groups_count] = grp; \
			detail->groups_count++; \
		} \
	} while(0)
#else
 #define PUSH_GROUP
#endif

	switch (BPF_CLASS(opcode)) {
	default:	// will never happen
		break;
	case BPF_CLASS_LD:
		PUSH_GROUP(BPF_GRP_LOAD);
		break;
	case BPF_CLASS_LDX:
		PUSH_GROUP(BPF_GRP_LOAD);
		break;
	case BPF_CLASS_ST:
		PUSH_GROUP(BPF_GRP_STORE);
		break;
	case BPF_CLASS_STX:
		PUSH_GROUP(BPF_GRP_STORE);
		break;
	case BPF_CLASS_ALU:
		id = op2insn_ALU(opcode);
		PUSH_GROUP(BPF_GRP_ALU);
		break;
	case BPF_CLASS_JMP:
		grp = BPF_GRP_JUMP;
		if (EBPF_MODE(ud)) {
			// TODO: use BPF_INSN_CALL / BPF_INSN_RETURN_R0 on MI to check
			if (opcode == 0x85)
				grp = BPF_GRP_CALL;
			else if (opcode == 0x95)
				grp = BPF_GRP_RETURN;
		}
		PUSH_GROUP(grp);
		break;
	case BPF_CLASS_RET:
		PUSH_GROUP(BPF_GRP_RETURN);
		break;
	// BPF_CLASS_MISC and BPF_CLASS_ALU64 have exactly same value
	case BPF_CLASS_MISC:
	/* case BPF_CLASS_ALU64: */
		if (EBPF_MODE(ud)) {
			// ALU64 in eBPF
			id = op2insn_ALU(opcode);
			PUSH_GROUP(BPF_GRP_ALU);
		}
		else {
			if (opcode & 0x80)
				id = BPF_INS_TXA;
			else
				id = BPF_INS_TAX;
			PUSH_GROUP(BPF_GRP_MISC);
		}
	}

	insn->id = id;
#undef PUSH_GROUP
}
