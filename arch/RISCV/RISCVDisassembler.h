/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_RISCVDISASSEMBLER_H
#define CS_RISCVDISASSEMBLER_H

#include "../../include/capstone/capstone.h"

#include "../../include/capstone/capstone.h"
#include "../../MCRegisterInfo.h"

void RISCV_init(MCRegisterInfo *MRI);

bool RISCV_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif
