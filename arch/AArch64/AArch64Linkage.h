/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org> 2022-2023 */

#ifndef CS_AARCH64_LINKAGE_H
#define CS_AARCH64_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

DecodeStatus AArch64_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
					 size_t ByteLen, MCInst *MI,
					 uint16_t *Size, uint64_t Address,
					 void *Info);
const char *AArch64_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);
void AArch64_LLVM_printInstruction(MCInst *MI, SStream *O,
				   void * /* MCRegisterInfo* */ info);

#endif // CS_AARCH64_LINKAGE_H
