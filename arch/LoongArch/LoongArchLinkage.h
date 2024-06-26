/* Capstone Disassembly Engine */
/* By Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifndef CS_LOONGARCH_LINKAGE_H
#define CS_LOONGARCH_LINKAGE_H

// Function definitions to call static LLVM functions.

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "capstone/capstone.h"

const char *LoongArch_LLVM_getRegisterName(unsigned RegNo, unsigned AltIdx);
void LoongArch_LLVM_printInst(MCInst *MI, uint64_t Address, const char *Annot,
			      SStream *O);
DecodeStatus LoongArch_LLVM_getInstruction(MCInst *MI, uint64_t *Size,
					   const uint8_t *Bytes,
					   size_t BytesLen, uint64_t Address,
					   SStream *CS);

#endif // CS_LOONGARCH_LINKAGE_H
