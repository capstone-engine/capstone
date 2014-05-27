/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_MIPSDISASSEMBLER_H
#define CS_MIPSDISASSEMBLER_H

#include "../../include/capstone.h"

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"

void Mips_init(MCRegisterInfo *MRI);

bool Mips_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

bool Mips64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif
