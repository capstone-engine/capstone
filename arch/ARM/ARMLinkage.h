/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_ARM_LINKAGE_H
#define CS_ARM_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

DecodeStatus ARM_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				     size_t ByteLen, MCInst *MI, uint16_t *Size,
				     uint64_t Address, void *Info);
const char *ARM_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);
void ARM_LLVM_printInstruction(MCInst *MI, SStream *O,
			       void * /* MCRegisterInfo* */ info);

#endif // CS_ARM_LINKAGE_H
