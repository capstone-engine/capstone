#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_wasm(csh handle, cs_insn *ins)
{
	cs_wasm *wasm;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	wasm = &(ins->detail->wasm);
	if (wasm->op_count > 0) {
		unsigned int i;

		printf("\tOperand count: %d\n", wasm->op_count);

		for (i = 0; i < wasm->op_count; i++) {
			switch (wasm->operands[i].type) {
			default:
				break;
			case WASM_OP_INT7:
				printf("\t\tOperand[%u] type: int7\n", i);
				printf("\t\tOperand[%u] value: %d\n", i,
				       wasm->operands[i].int7);
				break;
			case WASM_OP_UINT32:
				printf("\t\tOperand[%u] type: uint32\n", i);
				printf("\t\tOperand[%u] value: 0x%x\n", i,
				       wasm->operands[i].uint32);
				break;
			case WASM_OP_UINT64:
				printf("\t\tOperand[%u] type: uint64\n", i);
				printf("\t\tOperand[%u] value: 0x%" PRIx64 "\n",
				       i, wasm->operands[i].uint64);
				break;
			case WASM_OP_VARUINT32:
				printf("\t\tOperand[%u] type: varuint32\n", i);
				printf("\t\tOperand[%u] value: 0x%x\n", i,
				       wasm->operands[i].varuint32);
				break;
			case WASM_OP_VARUINT64:
				printf("\t\tOperand[%u] type: varuint64\n", i);
				printf("\t\tOperand[%u] value: 0x%" PRIx64 "\n",
				       i, wasm->operands[i].varuint64);
				break;
			}

			printf("\t\tOperand[%u] size: %u\n", i,
			       wasm->operands[i].size);
		}
	}
}
