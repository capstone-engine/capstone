/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPAINSTPRINTER_H
#define CS_HPPAINSTPRINTER_H

#include <capstone/capstone.h>

#include "../../MCInst.h"
#include "../../SStream.h"

struct SStream;

void HPPA_printInst(MCInst *MI, struct SStream *O, void *Info);

#endif
