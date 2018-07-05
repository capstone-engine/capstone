/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#include "NEOInstPrinter.h"
#include "NEOMapping.h"


void NEO_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	int opsize;

	// print mnemonic
	SStream_concat(O, NEO_insn_name((csh)MI->csh, MI->Opcode));

	opsize = neo_insn_opsize(MI->Opcode);
	if (opsize) {
		// print operand
		unsigned int i;

		SStream_concat0(O, "\t");
		for (i = 0; i < opsize; i++) {
			SStream_concat(O, "%02x", MI->neo_data[i]);
		}
	}
}
