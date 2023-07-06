/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_ALPHA_MAP_H
#define CS_ALPHA_MAP_H

#include <capstone/capstone.h>

// unsigned int Alpha_map_insn_id(cs_struct *h, unsigned int id);

// given internal insn id, return public instruction info
void Alpha_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *Alpha_insn_name(csh handle, unsigned int id);

const char *Alpha_group_name(csh handle, unsigned int id);

void Alpha_printInst(MCInst *MI, SStream *O, void *Info);
const char *Alpha_getRegisterName(csh handle, unsigned int id);

#endif
