/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_TRICOREINSTPRINTER_H
#define CS_TRICOREINSTPRINTER_H

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "./TriCoreMapping.h"

const char *TriCore_getRegisterName(csh handle, unsigned int id);

void TriCore_printInst(MCInst *MI, SStream *O, void *Info);

void TriCore_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci);

#endif
