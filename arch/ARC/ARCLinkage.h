/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

#ifndef CS_ARC_LINKAGE_H
#define CS_ARC_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

const char *ARC_LLVM_getRegisterName(unsigned RegNo);
void ARC_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			      SStream *O);
DecodeStatus ARC_LLVM_getInstruction(MCInst *MI, uint64_t *Size,
					   const uint8_t *Bytes,
					   size_t BytesLen, uint64_t Address,
					   SStream *CS);

#endif // CS_ARC_LINKAGE_H
