/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_ALPHA_MAP_H
#define CS_ALPHA_MAP_H

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include <capstone/capstone.h>

// unsigned int Alpha_map_insn_id(cs_struct *h, unsigned int id);

// given internal insn id, return public instruction info
void Alpha_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *Alpha_insn_name(csh handle, unsigned int id);

const char *Alpha_group_name(csh handle, unsigned int id);

void Alpha_printInst(MCInst *MI, SStream *O, void *Info);

const char *Alpha_getRegisterName(csh handle, unsigned int id);
bool Alpha_getInstruction(csh handle, const uint8_t *code,
								  size_t code_len, MCInst *instr,
								  uint16_t *size, uint64_t address, void *info);
void Alpha_init_cs_detail(MCInst *MI);
void Alpha_add_cs_detail(MCInst *MI, unsigned OpNum);

void Alpha_set_instr_map_data(MCInst *MI);
void Alpha_set_detail_op_imm(MCInst *MI, unsigned OpNum, alpha_op_type ImmType,
							 int64_t Imm);
void Alpha_set_detail_op_reg(MCInst *MI, unsigned OpNum, alpha_op_type Reg);

void Alpha_reg_access(const cs_insn *insn, cs_regs regs_read,
			uint8_t *regs_read_count, cs_regs regs_write,
			uint8_t *regs_write_count);

#endif
