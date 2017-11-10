/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_X86_MAP_H
#define CS_X86_MAP_H

#include "../../include/capstone.h"
#include "../../cs_priv.h"

// map sib_base to x86_reg
x86_reg x86_map_sib_base(int r);

// map sib_index to x86_reg
x86_reg x86_map_sib_index(int r);

// map seg_override to x86_reg
x86_reg x86_map_segment(int r);

// return name of regiser in friendly string
const char *X86_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

// return insn name, given insn id
const char *X86_insn_name(csh handle, unsigned int id);

// return group name, given group id
const char *X86_group_name(csh handle, unsigned int id);

// return register of given instruction id
// return 0 if not found
// this is to handle instructions embedding accumulate registers into AsmStrs[]
x86_reg X86_insn_reg_intel(unsigned int id);
x86_reg X86_insn_reg_att(unsigned int id);
bool X86_insn_reg_intel2(unsigned int id, x86_reg *reg1, x86_reg *reg2);
bool X86_insn_reg_att2(unsigned int id, x86_reg *reg1, x86_reg *reg2);

extern const uint64_t arch_masks[9];

// handle LOCK/REP/REPNE prefixes
// return True if we patch mnemonic, like in MULPD case
bool X86_lockrep(MCInst *MI, SStream *O);

// map registers to sizes
extern const uint8_t regsize_map_32[];
extern const uint8_t regsize_map_64[];

void op_addReg(MCInst *MI, int reg);
void op_addImm(MCInst *MI, int v);

void op_addAvxBroadcast(MCInst *MI, x86_avx_bcast v);

void op_addSseCC(MCInst *MI, int v);
void op_addAvxCC(MCInst *MI, int v);

void op_addAvxZeroOpmask(MCInst *MI);

void op_addAvxSae(MCInst *MI);

void op_addAvxRoundingMode(MCInst *MI, int v);

int X86_immediate_size(unsigned int id);

#endif
