/* Capstone Disassembly Engine */
/* By Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifndef CS_LOONGARCH_MAPPING_H
#define CS_LOONGARCH_MAPPING_H

#include "../../include/capstone/capstone.h"
#include "../../utils.h"
#include "../../Mapping.h"

typedef enum {
#include "LoongArchGenCSOpGroup.inc"
} loongarch_op_group;

void LoongArch_init_mri(MCRegisterInfo *MRI);

// return name of register in friendly string
const char *LoongArch_reg_name(csh handle, unsigned int reg);

void LoongArch_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info);

// given internal insn id, return public instruction ID
void LoongArch_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *LoongArch_insn_name(csh handle, unsigned int id);

const char *LoongArch_group_name(csh handle, unsigned int id);

void LoongArch_reg_access(const cs_insn *insn, cs_regs regs_read,
			  uint8_t *regs_read_count, cs_regs regs_write,
			  uint8_t *regs_write_count);

bool LoongArch_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			      MCInst *instr, uint16_t *size, uint64_t address,
			      void *info);

// cs_detail related functions
void LoongArch_init_cs_detail(MCInst *MI);
void LoongArch_add_cs_detail(MCInst *MI, int /* loongarch_op_group */ op_group,
			     va_list args);
static inline void add_cs_detail(MCInst *MI,
				 int /* loongarch_op_group */ op_group, ...)
{
	if (!MI->flat_insn->detail)
		return;
	va_list args;
	va_start(args, op_group);
	LoongArch_add_cs_detail(MI, op_group, args);
	va_end(args);
}

#endif // CS_LOONGARCH_MAPPING_H
