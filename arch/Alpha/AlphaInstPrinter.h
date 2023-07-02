#ifndef CS_ALPHAINSTPRINTER_H
#define CS_ALPHAINSTPRINTER_H

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "AlphaMapping.h"

const char *Alpha_getRegisterName(csh handle, unsigned int id);

void Alpha_printInst(MCInst *MI, SStream *O, void *Info);

void Alpha_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci);

#endif // CS_ALPHAINSTPRINTER_H