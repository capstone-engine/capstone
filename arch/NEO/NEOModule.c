/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#ifdef CAPSTONE_HAS_NEO

#include "../../cs_priv.h"
#include "NEODisassembler.h"
#include "NEOInstPrinter.h"
#include "NEOMapping.h"
#include "NEOModule.h"

cs_err NEO_global_init(cs_struct *ud)
{
	// verify if requested mode is valid
	if (ud->mode)
		return CS_ERR_MODE;

	ud->printer = NEO_printInst;
	ud->printer_info = NULL;
	ud->insn_id = NEO_get_insn_id;
	ud->insn_name = NEO_insn_name;
	ud->group_name = NEO_group_name;
	ud->disasm = NEO_getInstruction;

	return CS_ERR_OK;
}

cs_err NEO_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

#endif
