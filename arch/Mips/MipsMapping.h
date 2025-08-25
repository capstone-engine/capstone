/* Capstone Disassembly Engine */
/* By Giovanni Dante Grazioli, deroad <wargio@libero.it>, 2024 */

#ifndef CS_MIPS_MAPPING_H
#define CS_MIPS_MAPPING_H

#include "../../include/capstone/capstone.h"
#include "../../utils.h"
#include "../../Mapping.h"

typedef enum {
#include "MipsGenCSOpGroup.inc"
} mips_op_group;

void Mips_init_mri(MCRegisterInfo *MRI);

// return name of register in friendly string
const char *Mips_reg_name(csh handle, unsigned int reg);

void Mips_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);

// given internal insn id, return public instruction ID
void Mips_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *Mips_insn_name(csh handle, unsigned int id);

const char *Mips_group_name(csh handle, unsigned int id);

bool Mips_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info);

void Mips_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count);

// cs_detail related functions
void Mips_init_cs_detail(MCInst *MI);

void Mips_set_mem_access(MCInst *MI, bool status);

void Mips_add_cs_detail(MCInst *MI, mips_op_group op_group, va_list args);

static inline void add_cs_detail(MCInst *MI, mips_op_group op_group, ...)
{
	if (!detail_is_set(MI))
		return;
	va_list args;
	va_start(args, op_group);
	Mips_add_cs_detail(MI, op_group, args);
	va_end(args);
}

static inline void set_mem_access(MCInst *MI, bool status)
{
	if (!detail_is_set(MI))
		return;
	Mips_set_mem_access(MI, status);
}

#endif // CS_MIPS_MAPPING_H
