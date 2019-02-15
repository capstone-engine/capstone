/* Capstone testing regression */
/* By david942j <david942j@gmail.com>, 2019 */

#include "factory.h"

char *get_detail_bpf(csh *handle, cs_mode mode, cs_insn *ins)
{
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	if (ins->detail == NULL)
		return result;

	return result;
}
