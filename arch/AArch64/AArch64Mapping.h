/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_ARM64_MAP_H
#define CS_ARM64_MAP_H

#include "../../include/capstone.h"

// return name of regiser in friendly string
const char *AArch64_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *AArch64_insn_name(csh handle, unsigned int id);

const char *AArch64_group_name(csh handle, unsigned int id);

// map instruction name to public instruction ID
arm64_reg AArch64_map_insn(const char *name);

// map internal vregister to public register
arm64_reg AArch64_map_vregister(unsigned int r);

void arm64_op_addReg(MCInst *MI, int reg);

void arm64_op_addVectorArrSpecifier(MCInst * MI, int sp);

void arm64_op_addVectorElementSizeSpecifier(MCInst * MI, int sp);

void arm64_op_addFP(MCInst *MI, float fp);

void arm64_op_addImm(MCInst *MI, int64_t imm);

#endif
