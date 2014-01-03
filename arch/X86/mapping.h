/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_X86_MAP_H
#define CS_X86_MAP_H

#include "../../include/capstone.h"
#include "../../include/x86.h"

// map sib_base to x86_reg
x86_reg x86_map_sib_base(int r);

// map sib_index to x86_reg
x86_reg x86_map_sib_index(int r);

// map seg_override to x86_reg
x86_reg x86_map_segment(int r);

// map register name to x86_reg
x86_reg x86_map_regname(const char *reg);

// return name of regiser in friendly string
const char *X86_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void X86_get_insn_id(cs_insn *insn, unsigned int id, int detail);

// return insn name, given insn id
const char *X86_insn_name(csh handle, unsigned int id);

// return insn id, given insn mnemonic
x86_reg X86_map_insn(const char *mnem);

// given public insn id, return internal insn id
unsigned int X86_get_insn_id2(unsigned int insn_id);

// post printer for X86.
void X86_post_printer(csh handle, cs_insn *pub_insn, char *insn_asm);

// free insn cache
void X86_free_cache(void);

#endif
