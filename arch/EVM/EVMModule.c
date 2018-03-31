/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh, 2018 */

#ifdef CAPSTONE_HAS_ARM

#include "../../cs_priv.h"
#include "EVMDisassembler.h"
#include "EVMInstPrinter.h"
#include "EVMMapping.h"

static cs_err init(cs_struct *ud)
{
	// verify if requested mode is valid
	if (ud->mode)
		return CS_ERR_MODE;

	ud->printer = EVM_printInst;
	ud->printer_info = NULL;
	ud->insn_id = EVM_get_insn_id;
	ud->insn_name = EVM_insn_name;
	ud->group_name = EVM_group_name;
	ud->disasm = EVM_getInstruction;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

void EVM_enable(void)
{
	cs_arch_init[CS_ARCH_EVM] = init;
	cs_arch_option[CS_ARCH_EVM] = option;

	// support this arch
	all_arch |= (1 << CS_ARCH_EVM);
}

#endif
