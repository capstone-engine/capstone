#ifndef CAPSTONE_PPC_INSTPRINTER_H_2944CAE7EB5F4ACBB9C48F875CEEFFD0
#define CAPSTONE_PPC_INSTPRINTER_H_2944CAE7EB5F4ACBB9C48F875CEEFFD0

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

void PPC_printInst(MCInst *MI, SStream *O, void *Info);

#endif
