/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

#ifndef CS_ARC_MAP_H
#define CS_ARC_MAP_H

#include "../../Mapping.h"
#include "../../include/capstone/capstone.h"
#include "../../utils.h"

typedef enum {
#include "ARCGenCSOpGroup.inc"
} arc_op_group;

void ARC_init_mri(MCRegisterInfo *MRI);

// return name of register in friendly string
const char *ARC_reg_name(csh handle, unsigned int reg);

void ARC_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);

// given internal insn id, return public instruction ID
void ARC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *ARC_insn_name(csh handle, unsigned int id);

const char *ARC_group_name(csh handle, unsigned int id);

void ARC_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count);

bool ARC_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info);

// cs_detail related functions
void ARC_init_cs_detail(MCInst *MI);
void ARC_set_detail_op_imm(MCInst *MI, unsigned OpNum, arc_op_type ImmType,
			   int64_t Imm);
void ARC_add_cs_detail(MCInst *MI, int /* arc_op_group */ op_group,
		       va_list args);
static inline void add_cs_detail(MCInst *MI, int /* arc_op_group */ op_group,
				 ...)
{
	if (!detail_is_set(MI))
		return;
	va_list args;
	va_start(args, op_group);
	ARC_add_cs_detail(MI, op_group, args);
	va_end(args);
}

#endif