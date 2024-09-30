/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#ifndef XTENSA_DISASSEMBLER_H
#define XTENSA_DISASSEMBLER_H

#include "../../MCDisassembler.h"

DecodeStatus Xtensa_LLVM_getInstruction(MCInst *MI, uint16_t *Size,
					const uint8_t *Bytes,
					unsigned BytesSize, uint64_t Address);

#endif
