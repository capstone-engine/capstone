/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#ifndef CS_ETCA_INSTPRINTER_H
#define CS_ETCA_INSTPRINTER_H

#include "capstone/capstone.h"
#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../cs_priv.h"
#include "EtcaDisassembler.h"

struct SStream;

void Etca_printInst(MCInst *MI, struct SStream *O, void *Info);
const char *Etca_reg_name(csh handle, unsigned int reg);
void Etca_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
const char *Etca_insn_name(csh handle, unsigned int id);
const char *Etca_group_name(csh handle, unsigned int id);

#endif
