/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#ifndef XTENSA_MAPPING_H
#define XTENSA_MAPPING_H

#include "../../Mapping.h"

typedef enum {
#include "XtensaGenCSOpGroup.inc"
} xtensa_op_group;

void Xtensa_init_mri(MCRegisterInfo *mri);
void Xtensa_printer(MCInst *MI, SStream *OS, void *info);
bool Xtensa_disasm(csh handle, const uint8_t *code, size_t code_len,
		   MCInst *instr, uint16_t *size, uint64_t address, void *info);
const char *Xtensa_reg_name(csh handle, unsigned int id);
void Xtensa_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
const char *Xtensa_insn_name(csh handle, unsigned int id);
const char *Xtensa_group_name(csh handle, unsigned int id);
#ifndef CAPSTONE_DIET
void Xtensa_reg_access(const cs_insn *insn, cs_regs regs_read,
		       uint8_t *regs_read_count, cs_regs regs_write,
		       uint8_t *regs_write_count);
#endif

void Xtensa_add_cs_detail(MCInst *MI, xtensa_op_group op_group, va_list args);

static inline void add_cs_detail(MCInst *MI, xtensa_op_group op_group, ...)
{
	if (!detail_is_set(MI))
		return;
	va_list args;
	va_start(args, op_group);
	Xtensa_add_cs_detail(MI, op_group, args);
	va_end(args);
}

#endif
