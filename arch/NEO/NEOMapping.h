/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#include <capstone/capstone.h>

void NEO_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
const char *NEO_insn_name(csh handle, unsigned int id);
const char *NEO_group_name(csh handle, unsigned int id);
int neo_insn_opsize(unsigned int id);
