/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifdef CAPSTONE_HAS_BPF

#include "BPFDisassembler.h"
#include "BPFModule.h"

cs_err BPF_global_init(cs_struct *ud)
{
	ud->disasm = BPF_getInstruction;
	return CS_ERR_OK;
}

cs_err BPF_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		handle->mode = (cs_mode)value;
	}
	return CS_ERR_OK;
}

#endif
