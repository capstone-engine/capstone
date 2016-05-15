/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_XCOREDISASSEMBLER_H
#define CS_XCOREDISASSEMBLER_H

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void XCore_init(MCRegisterInfo *MRI);

bool XCore_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif

