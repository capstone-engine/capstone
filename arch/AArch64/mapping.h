#ifndef CAPSTONE_ARM64_MAP_H_525038A12C344A16AA6ABBCBF0728735
#define CAPSTONE_ARM64_MAP_H_525038A12C344A16AA6ABBCBF0728735

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../include/capstone.h"
#include "../../include/arm64.h"

// return name of regiser in friendly string
const char *AArch64_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_insn *insn, unsigned int id, int detail);

// given public insn id, return internal instruction ID
unsigned int AArch64_get_insn_id2(unsigned int id);

const char *AArch64_insn_name(csh handle, unsigned int id);

// map instruction name to public instruction ID
arm64_reg AArch64_map_insn(const char *name);

#endif
