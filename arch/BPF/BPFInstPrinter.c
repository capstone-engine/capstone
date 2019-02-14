/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#include "BPFInstPrinter.h"
#include "BPFMapping.h"

void BPF_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	int i;

	SStream_concat(O, BPF_insn_name((csh)MI->csh, MI->Opcode));
}
