/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <stdio.h> // debug
#include <string.h>
#include <assert.h>

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"

#include "TriCoreMapping.h"
#include "TriCoreLinkage.h"

#define GET_INSTRINFO_ENUM

#include "TriCoreGenInstrInfo.inc"

static const name_map group_name_maps[] = {
	{ TRICORE_GRP_INVALID, "invalid" },
	{ TRICORE_GRP_CALL, "call" },
	{ TRICORE_GRP_JUMP, "jump" },
#include "TriCoreGenCSFeatureName.inc"
};

static const insn_map mapping_insns[] = {
#include "TriCoreGenCSMappingInsn.inc"
};

static const map_insn_ops insn_operands[] = {
#include "TriCoreGenCSMappingInsnOp.inc"
};

static const char *const insn_names[] = {
#include "TriCoreGenCSMappingInsnName.inc"
};

// special alias insn
static const name_map alias_insn_names[] = { { 0, NULL } };

#ifndef CAPSTONE_DIET
static const tricore_reg flag_regs[] = { TRICORE_REG_PSW };
#endif // CAPSTONE_DIET

static inline void check_updates_flags(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI)) {
		return;
	}

	cs_detail *detail = get_detail(MI);

	for (int i = 0; i < detail->regs_write_count; ++i) {
		if (detail->regs_write[i] == 0)
			return;
		for (int j = 0; j < ARR_SIZE(flag_regs); ++j) {
			if (detail->regs_write[i] == flag_regs[j]) {
				detail->tricore.update_flags = true;
				return;
			}
		}
	}
#endif // CAPSTONE_DIET
}

static void set_instr_map_data(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	map_cs_id(MI, mapping_insns, ARR_SIZE(mapping_insns));
	map_implicit_reads(MI, mapping_insns);
	map_implicit_writes(MI, mapping_insns);
	map_groups(MI, mapping_insns);
	check_updates_flags(MI);
#endif
}

void TriCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used. Information is set after disassembly.
}

const char *TriCore_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= TRICORE_INS_ENDING)
		return NULL;

	const char *alias_name =
		id2name(alias_insn_names, ARR_SIZE(alias_insn_names), id);
	if (alias_name)
		return alias_name;

	return insn_names[id];
#else
	return NULL;
#endif
}

const char *TriCore_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

void TriCore_set_access(MCInst *MI)
{
#ifndef CAPSTONE_DIET
	if (!detail_is_set(MI))
		return;

	CS_ASSERT_RET(MI->Opcode < ARR_SIZE(insn_operands));

	cs_detail *detail = get_detail(MI);
	cs_tricore *tc = &(detail->tricore);
	for (int i = 0; i < tc->op_count; ++i) {
		cs_ac_type ac = map_get_op_access(MI, i);
		cs_tricore_op *op = &tc->operands[i];
		op->access = ac;
		cs_op_type op_type = map_get_op_type(MI, i);
		if (op_type != CS_OP_REG) {
			continue;
		}
		if (ac & CS_AC_READ) {
			detail->regs_read[detail->regs_read_count++] = op->reg;
		}
		if (ac & CS_AC_WRITE) {
			detail->regs_write[detail->regs_write_count++] =
				op->reg;
		}
	}
#endif
}

void TriCore_reg_access(const cs_insn *insn, cs_regs regs_read,
			uint8_t *regs_read_count, cs_regs regs_write,
			uint8_t *regs_write_count)
{
#ifndef CAPSTONE_DIET
	uint8_t read_count, write_count;
	cs_detail *detail = insn->detail;
	read_count = detail->regs_read_count;
	write_count = detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, detail->regs_read,
	       read_count * sizeof(detail->regs_read[0]));
	memcpy(regs_write, detail->regs_write,
	       write_count * sizeof(detail->regs_write[0]));

	// explicit registers
	cs_tricore *tc = &detail->tricore;
	for (uint8_t i = 0; i < tc->op_count; i++) {
		cs_tricore_op *op = &(tc->operands[i]);
		switch ((int)op->type) {
		case TRICORE_OP_REG:
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
		case TRICORE_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.base != ARM_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = (uint16_t)op->mem.base;
				read_count++;
			}
		default:
			break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
#endif
}

bool TriCore_disasm(csh handle, const uint8_t *code, size_t code_len,
		    MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	instr->MRI = (MCRegisterInfo *)info;
	if (instr->flat_insn->detail) {
		memset(instr->flat_insn->detail, 0, sizeof(cs_detail));
	}

	bool res = TriCore_LLVM_getInstruction(handle, code, code_len, instr,
					       size, address);
	if (!res)
		return res;
	set_instr_map_data(instr);
	return res;
}

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	MI->MRI = Info;
	TriCore_LLVM_printInst(MI, MI->address, O);
}

const char *TriCore_getRegisterName(csh handle, unsigned int RegNo)
{
	return TriCore_LLVM_getRegisterName(RegNo);
}

#endif // CAPSTONE_HAS_TRICORE
