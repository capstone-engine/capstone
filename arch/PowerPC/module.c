/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013 */

#include "../../cs_priv.h"
#include "../../MCRegisterInfo.h"
#include "PPCDisassembler.h"
#include "PPCInstPrinter.h"
//#include "mapping.h"


static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri = malloc(sizeof(*mri));

	PPC_init(mri);
	ud->printer = PPC_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	// ud->reg_name = PPC_reg_name;
	// ud->insn_id = PPC_get_insn_id;
	// ud->insn_name = PPC_insn_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax = value;

	return CS_ERR_OK;
}

static void __attribute__ ((constructor)) __init_mips__()
{
	arch_init[CS_ARCH_PPC] = init;
	arch_option[CS_ARCH_PPC] = option;

	// support this arch
	all_arch |= (1 << CS_ARCH_PPC);
}
