/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_ARM_MAP_H
#define CS_ARM_MAP_H

#include "../../include/capstone.h"
#include "../../include/arm.h"
#include "../../utils.h"

// return name of regiser in friendly string
const char *ARM_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction ID
void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *ARM_insn_name(csh handle, unsigned int id);

#endif
