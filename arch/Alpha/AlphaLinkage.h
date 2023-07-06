/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_ALPHA_LINKAGE_H
#define CS_ALPHA_LINKAGE_H

// Function defintions to call static LLVM functions.

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "AlphaMapping.h"

const char *Alpha_LLVM_getRegisterName(csh handle, unsigned int id);

void Alpha_LLVM_printInst(MCInst *MI, SStream *O, void *Info);

#endif // CS_ALPHA_LINKAGE_H