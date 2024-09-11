/* Capstone Disassembly Engine */
/* By Giovanni Dante Grazioli, deroad <wargio@libero.it>, 2024 */

#ifndef CS_MIPS_LINKAGE_H
#define CS_MIPS_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

const char *Mips_LLVM_getRegisterName(unsigned RegNo, bool noRegName);
void Mips_LLVM_printInst(MCInst *MI, uint64_t Address, SStream *O);
DecodeStatus Mips_LLVM_getInstruction(MCInst *Instr, uint64_t *Size,
				const uint8_t *Bytes, size_t BytesLen,
				uint64_t Address, SStream *CStream);

#endif // CS_MIPS_LINKAGE_H
