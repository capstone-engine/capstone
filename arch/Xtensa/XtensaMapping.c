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

#ifndef CAPSTONE_DIET

static const char *const insn_name_maps[] = {
#include "XtensaGenCSMappingInsnName.inc"
};

static const name_map group_name_maps[] = {
#include "XtensaGenCSFeatureName.inc"
};

const insn_map mapping_insns[] = {
#include "XtensaGenCSMappingInsn.inc"
};

static const map_insn_ops insn_operands[] = {
#include "XtensaGenCSMappingInsnOp.inc"
};

#endif

#define GET_REGINFO_MC_DESC
#include "XtensaGenRegisterInfo.inc"

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

	unsigned opcode = MCInst_getOpcode(MI);
	if (opcode > ARR_SIZE(insn_operands)) {
		return;
	}

	const map_insn_ops *ops = &insn_operands[opcode];
	cs_xtensa *detail = &MI->flat_insn->detail->xtensa;
	cs_xtensa_op *operand = detail->operands;
	for (int i = 0; i < ARR_SIZE(ops->ops); ++i) {
		const mapping_op *op = ops->ops + i;
		if (!op->access || !op->type) {
			break;
		}
		operand->access = op->access;
		operand->type = op->type;
		MCOperand *mc = MCInst_getOperand(MI, i);

#define check(_k) if ((op->type & (_k)) == (_k))
		check(CS_OP_IMM)
		{
			operand->imm = (int32_t)mc->ImmVal;
		}
		check(CS_OP_REG)
		{
			operand->reg = (uint8_t)mc->RegVal;
		}
		check(CS_OP_MEM_REG)
		{
			operand->mem.base = mc->RegVal;
		}
		check(CS_OP_MEM_IMM)
		{
			if (i > 0) {
				cs_xtensa_op *prev = (operand - 1);
				if (prev->type == CS_OP_MEM_REG &&
				    prev->access == op->access) {
					prev->type = Xtensa_OP_MEM;
					prev->mem.disp = mc->ImmVal;
					continue;
				}
			}
			operand->mem.disp = mc->ImmVal;
		}

		detail->op_count++;
		operand++;
	}
#endif
}

bool Xtensa_disasm(csh handle, const uint8_t *code, size_t code_len,
		   MCInst *instr, uint16_t *size, uint64_t address, void *info)
{
	DecodeStatus res = Xtensa_LLVM_getInstruction(instr, size, code,
						      code_len, address);
	if (res == MCDisassembler_Success) {
		set_instr_map_data(instr);
	}
	return res == MCDisassembler_Success;
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
		case Xtensa_OP_REG:
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
		case Xtensa_OP_MEM:
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
