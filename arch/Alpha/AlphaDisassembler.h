#ifndef CS_ALPHADISASSEMBLER_H
#define CS_ALPHADISASSEMBLER_H

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include <capstone/capstone.h>
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void Alpha_init(MCRegisterInfo *MRI);

bool Alpha_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			    MCInst *instr, uint16_t *size, uint64_t address,
			    void *info);

#endif // CS_ALPHADISASSEMBLER_H