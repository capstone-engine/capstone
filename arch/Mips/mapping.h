/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_MIPS_MAP_H
#define CS_MIPS_MAP_H

#include "../../include/capstone.h"
#include "../../include/mips.h"

// return name of regiser in friendly string
const char *Mips_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void Mips_get_insn_id(cs_insn *insn, unsigned int id, int detail);

// given public insn id, return internal insn id
unsigned int Mips_get_insn_id2(unsigned int id);

// given public insn id, return internal insn id
const char *Mips_insn_name(csh handle, unsigned int id);

// map instruction name to instruction ID
mips_reg Mips_map_insn(const char *name);

// map internal raw register to 'public' register
mips_reg Mips_map_register(unsigned int r);

// free insn cache
void Mips_free_cache(void);

#endif
