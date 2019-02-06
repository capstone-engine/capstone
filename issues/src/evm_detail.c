#include "factory.h"

char *get_detail_evm(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_evm *evm;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return result;

	evm = &(ins->detail->evm);

	if (evm->pop)
		addStr(result, " | Pop: %u", evm->pop);

	if (evm->push)
		addStr(result, " | Push: %u", evm->push);

	if (evm->fee)
		addStr(result, " | Gas fee: %u", evm->fee);

	return result;
}
