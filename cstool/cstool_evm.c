#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_evm(csh handle, cs_insn *ins)
{
	cs_evm *evm;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	evm = &(ins->detail->evm);

	if (evm->pop)
		printf("\tPop:     %u\n", evm->pop);

	if (evm->push)
		printf("\tPush:    %u\n", evm->push);

	if (evm->fee)
		printf("\tGas fee: %u\n", evm->fee);
}
