#ifndef CAPSTONE_MIPS_DISASSEMBLER_H_C16F38B2CCB946019DD9EB928049FFF1
#define CAPSTONE_MIPS_DISASSEMBLER_H_C16F38B2CCB946019DD9EB928049FFF1

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../include/capstone.h"

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"

void Mips_init(MCRegisterInfo *MRI);

bool Mips_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

bool Mips64_getInstruction(csh handle, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif
