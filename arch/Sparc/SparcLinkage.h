#ifndef CS_SPARC_LINKAGE_H
#define CS_SPARC_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../SStream.h"

DecodeStatus Sparc_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				       size_t ByteLen, MCInst *MI,
				       uint16_t *Size, uint64_t Address,
				       void *Info);
const char *Sparc_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);
void Sparc_LLVM_printInstruction(MCInst *MI, SStream *O,
				 void * /* MCRegisterInfo* */ info);
void Sparc_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			  SStream *O);

#endif // CS_SPARC_LINKAGE_H
