#ifndef CAPSTONE_ARM_DISASSEMBLER_H_4419C527F11548B394B1BC48D6B4BD56
#define CAPSTONE_ARM_DISASSEMBLER_H_4419C527F11548B394B1BC48D6B4BD56

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"

void ARM_init(MCRegisterInfo *MRI);

bool ARM_getInstruction(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);

bool Thumb_getInstruction(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);

uint64_t ARM_getFeatureBits(int mode);

#endif
