#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

void print_string_hex(char *comment, unsigned char *str, size_t len);

void print_insn_detail_neo(csh handle, cs_insn *ins)
{
	cs_neo *neo;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	neo = &(ins->detail->neo);

	if (neo->op_size)
		printf("\tOp_size: %u\n", neo->op_size);

	if (neo->pop)
		printf("\tPop:     %u\n", neo->pop);

	if (neo->push)
		printf("\tPush:    %u\n", neo->push);

	if (neo->fee) {
		switch(neo->fee) {
			default:
				break;
			case NEO_FEE_0:
				printf("\tGas fee: 0\n");
				break;
			case NEO_FEE_01:
				printf("\tGas fee: 0.1\n");
				break;
			case NEO_FEE_001:
				printf("\tGas fee: 0.01\n");
				break;
			case NEO_FEE_002:
				printf("\tGas fee: 0.02\n");
				break;
			case NEO_FEE_0001:
				printf("\tGas fee: 0.001\n");
				break;
		}
	}
}
