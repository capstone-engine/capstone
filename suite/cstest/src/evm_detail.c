/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

char *get_detail_evm(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_evm *evm;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	evm = &(ins->detail->evm);

	if (evm->pop)
		add_str(&result, " ; Pop: %u", evm->pop);

	if (evm->push)
		add_str(&result, " ; Push: %u", evm->push);

	if (evm->fee)
		add_str(&result, " ; Gas fee: %u", evm->fee);

	return result;
}
