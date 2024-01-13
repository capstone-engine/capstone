/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include "HPPADisassembler.h"
#include "HPPAInstPrinter.h"
#include "HPPAMapping.h"
#include "HPPAModule.h"

cs_err HPPA_global_init(cs_struct *ud)
{
	ud->printer = HPPA_printInst;
	ud->reg_name = HPPA_reg_name;
	ud->insn_id = HPPA_get_insn_id;
	ud->insn_name = HPPA_insn_name;
	ud->group_name = HPPA_group_name;
#ifndef CAPSTONE_DIET
	ud->reg_access = HPPA_reg_access;
#endif
	ud->disasm = HPPA_getInstruction;

	return CS_ERR_OK;
}

cs_err HPPA_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE)
		handle->mode = (cs_mode)value;

	return CS_ERR_OK;
}

#endif