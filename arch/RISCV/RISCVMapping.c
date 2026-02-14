#include "capstone/cs_operand.h"
#include "capstone/riscv.h"
#include <stdint.h>
#include <float.h>
#include <math.h>
#ifdef CAPSTONE_HAS_RISCV

#include <string.h>

#include "../../Mapping.h"
#include "../../cs_simple_types.h"
#include "../../utils.h"

#include "RISCVMapping.h"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "RISCVGenRegisterInfo.inc"

#include "RISCVInstPrinter.h"

const char *RISCV_reg_name(csh handle, unsigned int reg)
{
	int syntax_opt = ((cs_struct *)(uintptr_t)handle)->syntax;

	if (syntax_opt & CS_OPT_SYNTAX_NOREGNAME) {
		return RISCV_LLVM_getRegisterName(reg, RISCV_NoRegAltName);
	}
	return RISCV_LLVM_getRegisterName(reg, RISCV_ABIRegAltName);
}

static const insn_map insns[] = {
#include "RISCVGenCSMappingInsn.inc"
};

const insn_map *RISCV_insns = insns;
const unsigned int RISCV_insn_count = ARR_SIZE(insns);

#ifndef CAPSTONE_DIET

static const map_insn_ops insn_operands[] = {
#include "RISCVGenCSMappingInsnOp.inc"
};

#endif

void RISCV_add_cs_detail_0(MCInst *MI, riscv_op_group opgroup, unsigned OpNum)
{
	if (!detail_is_set(MI))
		return;
	// are not "true" arguments and has no Capstone equivalent
	if (opgroup == RISCV_OP_GROUP_FRMArg ||
	    opgroup == RISCV_OP_GROUP_FRMArgLegacy)
		return;

	if (opgroup == RISCV_OP_GROUP_FPImmOperand) {
		unsigned Imm = (unsigned)MCInst_getOperand(MI, OpNum)->ImmVal;
		cs_riscv_op *op = RISCV_get_detail_op_at(MI, OpNum);
		op->type = RISCV_OP_FP;
		op->access = (cs_ac_type)map_get_op_access(MI, OpNum);
		switch (Imm) {
		case 1: // min
			switch (MI->Opcode) {
			case RISCV_FLI_S:
				op->dimm = (double)FLT_MIN;
				break;
			case RISCV_FLI_D:
				op->dimm = (double)DBL_MIN;
				break;
			case RISCV_FLI_H:
				op->dimm = 6.103515625e-05;
				break;
			default:
				op->dimm = 0.0;
				break;
			}
			break;
		case 30: // inf
			op->dimm = INFINITY;
			break;
		case 31: // nan
			op->dimm = NAN;
			break;
		default:
			op->dimm = (double)getFPImm(Imm);
			break;
		}
		RISCV_inc_op_count(MI);
		return;
	}
	cs_riscv_op *op = RISCV_get_detail_op_at(MI, OpNum);
	op->type = (riscv_op_type)map_get_op_type(MI, OpNum);
	op->access = (cs_ac_type)map_get_op_access(MI, OpNum);
	switch (map_get_op_type(MI, OpNum)) {
	case CS_OP_REG:
		op->reg = MCInst_getOperand(MI, OpNum)->RegVal;
		break;
	case CS_OP_MEM:
		op->mem.base = 0;
		op->mem.disp = MCInst_getOperand(MI, OpNum)->ImmVal;
		break;
	case CS_OP_IMM: {
		uint64_t val = MCInst_getOperand(MI, OpNum)->ImmVal;
		if (opgroup != RISCV_OP_GROUP_CSRSystemRegister) {
			op->imm = val;
			if (opgroup == RISCV_OP_GROUP_BranchOperand) {
				op->imm += MI->address;
			}
		} else /* system register read-write */ {
			op->type = RISCV_OP_CSR;
			op->csr = val;
			// CSR instruction always read-writes the system operand
			op->access = CS_AC_READ_WRITE;
		}
		break;
	}
	case CS_OP_MEM_REG:
		op->type = (riscv_op_type)CS_OP_MEM;
		op->mem.base = MCInst_getOperand(MI, OpNum)->RegVal;
		break;
	case CS_OP_MEM_IMM:
		// fill in the disp in the last operand
		op = RISCV_get_detail_op_at(MI, OpNum - 1);
		op->type = (riscv_op_type)CS_OP_MEM;
		op->mem.disp = MCInst_getOperand(MI, OpNum)->ImmVal;
		RISCV_dec_op_count(
			MI); // don't increase the count, cancel the coming increment
		break;
	case CS_OP_INVALID:
		break;
	default: {
		CS_ASSERT(0 && "unhandled operand type");
	}
	}
	RISCV_inc_op_count(MI);
}

static inline void RISCV_add_adhoc_groups(MCInst *MI);

void RISCV_add_groups(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;

	get_detail(MI)->groups_count = 0;

#ifndef CAPSTONE_DIET
	int i = 0;
	while (insns[MI->Opcode].groups[i] != 0) {
		add_group(MI, insns[MI->Opcode].groups[i]);
		i++;
	}
#endif

	RISCV_add_adhoc_groups(MI);
}

enum {
#define GET_ENUM_VALUES_RISCVOpcode
#include "RISCVGenCSSystemOperandsEnum.inc"
};

static inline void RISCV_add_privileged_group(MCInst *MI)
{
	const uint8_t *bytes = MI->flat_insn->bytes;
	uint8_t opcode = bytes[0] & 0x80;
	// no privileged instruction has a major opcode other than SYSTEM
	if (opcode != RISCV_RISCVOPCODE_SYSTEM) {
		return;
	}
	uint8_t func3 = (bytes[1] >> 4) & 0x7;
	// no privileged instruction has a minor opcode other than PRIV or PRIVM
	if (func3 != 0 && func3 != 0x4) {
		return;
	}
	uint16_t func12 = readBytes16(MI, &(bytes[2])) >> 4;
	// ecall and ebreak has SYSTEM and PRIV but aren't privileged
	if (func12 == 0 || func12 == 1) {
		return;
	}
	uint8_t func6 = func12 >> 6;
	// a subspace under extension-defined custom SYSTEM instructions that is not privileged
	if (func6 == 0x23 || func6 == 0x33) {
		return;
	}
	add_group(MI, RISCV_GRP_PRIVILEGE);
}

static inline void RISCV_add_interrupt_group(MCInst *MI)
{
	if (MI->Opcode == RISCV_ECALL || MI->Opcode == RISCV_EBREAK) {
		add_group(MI, RISCV_GRP_INT);
	}
}

static inline void RISCV_add_interrupt_ret_group(MCInst *MI)
{
	if (MI->Opcode == RISCV_MRET || MI->Opcode == RISCV_SRET) {
		add_group(MI, RISCV_GRP_IRET);
	}
}

// calls are implemented in RISCV as plain jumps that happen to set a link register containing the return address
// but this link register could be given as the null register x0, discarding the return address and making them jumps
static inline void RISCV_add_call_group(MCInst *MI)
{
	if (MI->Opcode == RISCV_JAL || MI->Opcode == RISCV_JALR) {
		cs_riscv_op *op = RISCV_get_detail_op_at(MI, 0);
		if ((op->type == (riscv_op_type)CS_OP_REG) &&
		    op->reg != RISCV_REG_X0 && (op->access & CS_AC_WRITE)) {
			add_group(MI, RISCV_GRP_CALL);
		}
		if (MI->Opcode == RISCV_JAL) {
			add_group(MI, RISCV_GRP_BRANCH_RELATIVE);
		}
	}
}

// returns are implemented in RISCV as a plain indirect jump that happen to reference the return address register ra == x1
static inline void RISCV_add_ret_group(MCInst *MI)
{
	if (MI->Opcode == RISCV_C_JR) {
		// indirect jumps whose source is ra
		cs_riscv_op *op = RISCV_get_detail_op_at(MI, 0);
		if ((op->type == (riscv_op_type)CS_OP_REG) &&
		    op->reg == RISCV_REG_X1) {
			add_group(MI, RISCV_GRP_RET);
		} else {
			add_group(MI, RISCV_GRP_JUMP);
		}
	}
	if (MI->Opcode == RISCV_JALR) {
		// indirect jumps whose source is ra
		cs_riscv_op *dstreg = RISCV_get_detail_op_at(MI, 0);
		cs_riscv_op *op = RISCV_get_detail_op_at(MI, 1);
		cs_riscv_op *op2 = RISCV_get_detail_op_at(MI, 2);
		if ((op->type == (riscv_op_type)CS_OP_REG) &&
		    op->reg == RISCV_REG_X1 &&
		    op2->type == (riscv_op_type)CS_OP_IMM && op2->imm == 0 &&
		    dstreg->type == (riscv_op_type)CS_OP_REG &&
		    dstreg->reg == RISCV_REG_X0) {
			add_group(MI, RISCV_GRP_RET);
		} else {
			if (!((dstreg->type == (riscv_op_type)CS_OP_REG) &&
			      dstreg->reg != RISCV_REG_X0 &&
			      (dstreg->access & CS_AC_WRITE))) {
				add_group(MI, RISCV_GRP_JUMP);
			}
		}
	}
}

static inline void RISCV_add_adhoc_groups(MCInst *MI)
{
	RISCV_add_privileged_group(MI);
	RISCV_add_interrupt_group(MI);
	RISCV_add_interrupt_ret_group(MI);
	RISCV_add_call_group(MI);
	RISCV_add_ret_group(MI);
}

// for weird reasons some instructions end up with valid operands that are
// interspersed with invalid operands, i.e. the operands array is an "island"
// of valid operands with invalid gaps between them, this function will compactify
// all the valid operands and pad the rest of the array to invalid
void RISCV_compact_operands(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;
	cs_riscv_op *ops = RISCV_get_detail(MI)->operands;
	unsigned int write_pos = 0;

	// Move valid elements to front
	for (unsigned int read_pos = 0; read_pos < NUM_RISCV_OPS; read_pos++) {
		if (ops[read_pos].type != (riscv_op_type)CS_OP_INVALID) {
			if (write_pos != read_pos) {
				ops[write_pos] = ops[read_pos];
			}
			write_pos++;
		}
	}
	// fill the rest, if any, with invalid
	memset((void *)(&ops[write_pos]), CS_OP_INVALID,
	       (NUM_RISCV_OPS - write_pos) * sizeof(cs_riscv_op));
}

// some RISC-V instructions have only 2 apparent operands, one of them is read-write
// the actual operand information for those instruction should have 3 operands, the first and second are the same operand,
// but once with read and once write access
// when those instructions are disassembled only the operand entry with the read access is used,
// and therefore the read-write operand is wrongly classified as only-read
// this logic tries to correct that
void RISCV_add_missing_write_access(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;
	if (!isCompressed(MI))
		return;

	cs_riscv *riscv_details = RISCV_get_detail(MI);
	cs_riscv_op *ops = riscv_details->operands;
	// make the detection condition as specific as possible
	// so it doesn't accidentally trigger for other cases
	if (riscv_details->op_count == 2 && ops[0].type == RISCV_OP_INVALID &&
	    ops[1].type == RISCV_OP_REG && ops[1].access == CS_AC_READ) {
		ops[1].access |= CS_AC_WRITE;
	}
}

// given internal insn id, return public instruction info
void RISCV_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn_map const *insn_map = NULL;

	if ((insn_map = lookup_insn_map(h, id))) {
		insn->id = insn_map->mapid;

		if (h->detail_opt) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insn_map->regs_use,
			       sizeof(insn_map->regs_use));
			insn->detail->regs_read_count =
				(uint8_t)count_positive(insn_map->regs_use);

			memcpy(insn->detail->regs_write, insn_map->regs_mod,
			       sizeof(insn_map->regs_mod));
			insn->detail->regs_write_count =
				(uint8_t)count_positive(insn_map->regs_mod);

			memcpy(insn->detail->groups, insn_map->groups,
			       sizeof(insn_map->groups));
			insn->detail->groups_count =
				(uint8_t)count_positive8(insn_map->groups);

			if (insn_map->branch || insn_map->indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail
					->groups[insn->detail->groups_count] =
					RISCV_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

static const char *const insn_name_maps[] = {
	/*RISCV_INS_INVALID:*/ NULL,

#include "RISCVGenCSMappingInsnName.inc"
};

const char *RISCV_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= RISCV_INS_ENDING)
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ RISCV_GRP_INVALID, NULL },
	{ RISCV_GRP_JUMP, "jump" },
	{ RISCV_GRP_CALL, "call" },
	{ RISCV_GRP_RET, "ret" },
	{ RISCV_GRP_INT, "int" },
	{ RISCV_GRP_IRET, "iret" },
	{ RISCV_GRP_PRIVILEGE, "privileged" },
	{ RISCV_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture specific
#include "RISCVGenCSFeatureName.inc"

	{ RISCV_GRP_ENDING, NULL }
};
#endif

const char *RISCV_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	// if past the end
	if (id >= RISCV_GRP_ENDING ||
	    // or in the encoding gap between generic groups and arch-specific groups
	    (id > RISCV_GRP_BRANCH_RELATIVE && id < RISCV_FEATURE_HASSTDEXTI))
		return NULL;
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
riscv_insn RISCV_map_insn(const char *name)
{
	unsigned int i;
	for (i = 1; i < ARR_SIZE(insn_name_maps); i++) {
		if (!strcmp(name, insn_name_maps[i]))
			return i;
	}
	return RISCV_INS_INVALID;
}

void RISCV_init(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, RISCVRegDesc, RISCV_REG_ENDING,
					  0, 0, RISCVMCRegisterClasses,
					  ARR_SIZE(RISCVMCRegisterClasses), 0,
					  0, RISCVRegDiffLists, 0,
					  RISCVSubRegIdxLists,
					  ARR_SIZE(RISCVSubRegIdxLists), 0);
}

#endif
