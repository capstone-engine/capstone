/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */
/* M68K Backend by Daniel Collin <daniel@collin.com> 2015 */

#ifdef CAPSTONE_HAS_M68K

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "M68KDisassembler.h"

static cs_err init(cs_struct *ud)
{
	ud->printer = M68K_printInst;
	ud->printer_info = 0;
	ud->getinsn_info = 0;
	ud->disasm = M68K_getInstruction;
	ud->skipdata_size = 2;
	ud->post_printer = 0;

	ud->reg_name = M68K_reg_name;
	ud->insn_id = M68K_get_insn_id;
	ud->insn_name = M68K_insn_name;
	ud->group_name = M68K_group_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

void M68K_enable(void)
{
	arch_init[CS_ARCH_M68K] = init;
	arch_option[CS_ARCH_M68K] = option;

	// support this arch
	all_arch |= (1 << CS_ARCH_M68K);
}

#endif

