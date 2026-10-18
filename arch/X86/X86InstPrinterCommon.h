/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_X86_INSTPRINTERCOMMON_H
#define CS_X86_INSTPRINTERCOMMON_H

#include "../../MCInst.h"
#include "../../SStream.h"

#define CS_X86_MAXIMUM_OPERAND_SIZE 6

void printSSEAVXCC(MCInst *MI, unsigned Op, SStream *O);
void printXOPCC(MCInst *MI, unsigned Op, SStream *O);
void printRoundingControl(MCInst *MI, unsigned Op, SStream *O);
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_ATT_DISABLE)
void X86_printInst_detail_syntax(MCInst *MI, SStream *OS, void *info,
				 void (*text)(MCInst *, SStream *, void *),
				 void (*detail)(MCInst *, SStream *, void *),
				 int detail_syntax);
#endif

#endif
