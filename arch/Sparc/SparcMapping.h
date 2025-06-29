/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_SPARC_MAP_H
#define CS_SPARC_MAP_H

#include "../../utils.h"
#include "SparcMCTargetDesc.h"
#include "SparcLinkage.h"
#include <capstone/capstone.h>

typedef enum {
#include "SparcGenCSOpGroup.inc"
} sparc_op_group;

void Sparc_add_cs_detail_0(MCInst *MI, sparc_op_group op_group, unsigned OpNo);

// return name of register in friendly string
const char *Sparc_reg_name(csh handle, unsigned int reg);

void Sparc_init_mri(MCRegisterInfo *MRI);
void Sparc_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info);
bool Sparc_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			      MCInst *instr, uint16_t *size, uint64_t address,
			      void *info);
// given internal insn id, return public instruction info
void Sparc_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *Sparc_insn_name(csh handle, unsigned int id);

const char *Sparc_group_name(csh handle, unsigned int id);
void Sparc_set_detail_op_imm(MCInst *MI, unsigned OpNum,
				 sparc_op_type ImmType, int64_t Imm);
void Sparc_set_detail_op_reg(MCInst *MI, unsigned OpNum, sparc_reg Reg);
void Sparc_add_cs_detail_0(MCInst *MI, sparc_op_group op_group, unsigned OpNo);
void Sparc_set_instr_map_data(MCInst *MI);

#endif

