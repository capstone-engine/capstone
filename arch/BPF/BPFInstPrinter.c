/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#include "BPFConstants.h"
#include "BPFInstPrinter.h"
#include "BPFMapping.h"

/*
 * 1. human readable mnemonic
 * 2. set pubOpcode (BPF_INSN_*)
 * 3. set detail->bpf.operands
 * */
void BPF_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	int i;
	cs_insn insn;

	/* set pubOpcode */
	insn.detail = NULL;
	BPF_get_insn_id((cs_struct*)MI->csh, &insn, MCInst_getOpcode(MI));
	MCInst_setOpcodePub(MI, insn.id);

	SStream_concat(O, BPF_insn_name((csh)MI->csh, insn.id));
	if (MI->flat_insn->detail) {
		MI->flat_insn->detail->bpf.op_count = MCInst_getNumOperands(MI);
	}
}
