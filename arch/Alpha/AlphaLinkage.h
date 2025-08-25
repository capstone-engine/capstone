/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_ALPHA_LINKAGE_H
#define CS_ALPHA_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "AlphaMapping.h"

const char *Alpha_LLVM_getRegisterName(csh handle, unsigned int id);
void Alpha_LLVM_printInstruction(MCInst *MI, SStream *O, void *Info);
DecodeStatus Alpha_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				       size_t ByteLen, MCInst *MI,
				       uint16_t *Size, uint64_t Address,
				       void *Info);

#endif // CS_ALPHA_LINKAGE_H