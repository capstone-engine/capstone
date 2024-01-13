/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPA_DISASSEMBLER_H
#define CS_HPPA_DISASSEMBLER_H

#include "../../MCInst.h"

bool HPPA_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info);

#endif