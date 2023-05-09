/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_TRICORE_MAP_H
#define CS_TRICORE_MAP_H

#include <capstone/capstone.h>

unsigned int TriCore_map_insn_id(cs_struct *h, unsigned int id);

// given internal insn id, return public instruction info
void TriCore_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *TriCore_insn_name(csh handle, unsigned int id);

const char *TriCore_group_name(csh handle, unsigned int id);

cs_err TRICORE_global_init(cs_struct *ud);
cs_err TRICORE_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif
