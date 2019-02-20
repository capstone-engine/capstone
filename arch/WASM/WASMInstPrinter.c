/* Capstone Disassembly Engine */
/* By Spike, xwings  2019 */

#include "WASMInstPrinter.h"
#include "WASMMapping.h"


void WASM_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	int i;

	SStream_concat(O, WASM_insn_name((csh)MI->csh, MI->Opcode));

	switch (MI->wasm_data.type) {
		default:
			break;

		case WASM_OP_VARUINT32:
			SStream_concat(O, "\t0x%x", MI->wasm_data.varuint32);
			break;

		case WASM_OP_VARUINT64:
			SStream_concat(O, "\t0x%lx", MI->wasm_data.varuint64);
			break;

		case WASM_OP_UINT32:
			SStream_concat(O, "\t0x%2" PRIx32, MI->wasm_data.uint32);
			break;

		case WASM_OP_UINT64:
			SStream_concat(O, "\t0x%2" PRIx64, MI->wasm_data.uint64);
			break;

		case WASM_OP_IMM:
			SStream_concat(O, "\t0x%x, 0x%x", MI->wasm_data.immediate[0], MI->wasm_data.immediate[1]);
			break;

		case WASM_OP_INT7:
			SStream_concat(O, "\t%d", MI->wasm_data.int7);
			break;

		case WASM_OP_BRTABLE:
			SStream_concat(O, "\t0x%x, [", MI->wasm_data.brtable.length);
			for (i = 0; i < MI->wasm_data.brtable.length; i++) {
				if (i == 0) {
					SStream_concat(O, "0x%x", MI->wasm_data.brtable.target[i]);
				} else {
					SStream_concat(O, ",0x%x", MI->wasm_data.brtable.target[i]);
				}
			}

			SStream_concat(O, "], 0x%x", MI->wasm_data.brtable.default_target);
			cs_mem_free(MI->wasm_data.brtable.target);

			break;
	}
}
