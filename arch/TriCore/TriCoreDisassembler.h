/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_TRICOREDISASSEMBLER_H
#define CS_TRICOREDISASSEMBLER_H

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include <capstone/capstone.h>
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void TriCore_init(MCRegisterInfo *MRI);

bool TriCore_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			    MCInst *instr, uint16_t *size, uint64_t address,
			    void *info);

bool TriCore_getFeatureBits(unsigned int mode, unsigned int feature);

#endif
