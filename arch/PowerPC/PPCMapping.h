/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_PPC_MAP_H
#define CS_PPC_MAP_H

#include "../../include/capstone.h"
#include "../../include/ppc.h"

// return name of regiser in friendly string
const char *PPC_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void PPC_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

// given public insn id, return internal insn id
unsigned int PPC_get_insn_id2(unsigned int id);

// given public insn id, return internal insn id
const char *PPC_insn_name(csh handle, unsigned int id);

// map instruction name to instruction ID
ppc_reg PPC_map_insn(const char *name);

// map internal raw register to 'public' register
ppc_reg PPC_map_register(unsigned int r);

#endif

