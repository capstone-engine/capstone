/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_SPARC_MAP_H
#define CS_SPARC_MAP_H

#include "../../include/capstone.h"

// return name of regiser in friendly string
const char *Sparc_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void Sparc_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *Sparc_insn_name(csh handle, unsigned int id);

// map internal raw register to 'public' register
sparc_reg Sparc_map_register(unsigned int r);

#endif

