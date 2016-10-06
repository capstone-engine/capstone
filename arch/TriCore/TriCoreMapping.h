/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_TRICORE_MAP_H
#define CS_TRICORE_MAP_H

#include "../../include/capstone.h"

// return name of regiser in friendly string
const char *TriCore_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void TriCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *TriCore_insn_name(csh handle, unsigned int id);

const char *TriCore_group_name(csh handle, unsigned int id);

// map internal raw register to 'public' register
tricore_reg TriCore_map_register(unsigned int r);

#endif

