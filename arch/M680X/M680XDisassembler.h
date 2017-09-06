/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#ifndef CS_M680XDISASSEMBLER_H
#define CS_M680XDISASSEMBLER_H

#include "../../MCInst.h"

bool M680X_getInstruction(csh ud, const uint8_t *code, size_t code_len,
	MCInst *instr, uint16_t *size, uint64_t address, void *info);
void M680X_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

#endif

