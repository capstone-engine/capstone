/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPAINSTPRINTER_H
#define CS_HPPAINSTPRINTER_H

#include <capstone/capstone.h>

#include "../../MCInst.h"
#include "../../SStream.h"

struct pa_insn {
	hppa_insn insn;
	hppa_insn_group grp;
};

struct pa_insn_fmt {
	hppa_insn insn_id;
	const char *format;
	bool is_alternative; ///< true if some completer affects the instruction format
};

void HPPA_printInst(MCInst *MI, SStream *O, void *Info);

#endif
