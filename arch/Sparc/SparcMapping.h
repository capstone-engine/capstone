/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_SPARC_MAP_H
#define CS_SPARC_MAP_H

#include "../../utils.h"
#include "SparcMCTargetDesc.h"
#include "SparcLinkage.h"
#include <capstone/capstone.h>

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

#endif

