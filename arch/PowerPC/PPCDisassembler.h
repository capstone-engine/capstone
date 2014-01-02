#ifndef CAPSTONE_PPC_DISASSEMBLER_H_5E7B0E85AA174450960026C08371F746
#define CAPSTONE_PPC_DISASSEMBLER_H_5E7B0E85AA174450960026C08371F746

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdint.h>

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void PPC_init(MCRegisterInfo *MRI);

bool PPC_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif

