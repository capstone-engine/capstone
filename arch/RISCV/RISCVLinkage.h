#ifndef CS_MIPS_LINKAGE_H
#define CS_MIPS_LINKAGE_H

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

bool RISCV_LLVM_getInstruction(csh handle, const uint8_t *Bytes, size_t ByteLen,
			       MCInst *MI, uint16_t *Size, uint64_t Address,
			       void *Info);
const char *RISCV_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);
void RISCV_LLVM_printInstruction(MCInst *MI, SStream *O,
				 void * /* MCRegisterInfo* */ info);

#endif // CS_MIPS_LINKAGE_H