/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "XtensaInstPrinter.h"
#include "XtensaMapping.h"
#include "XtensaModule.h"

cs_err Xtensa_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_calloc(1, sizeof(*mri));

	Xtensa_init_mri(mri);
	ud->printer = Xtensa_printer;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = Xtensa_disasm;
	ud->reg_name = Xtensa_reg_name;
	ud->insn_id = Xtensa_insn_id;
	ud->insn_name = Xtensa_insn_name;
	ud->group_name = Xtensa_group_name;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = Xtensa_reg_access;
#endif

	return CS_ERR_OK;
}

cs_err Xtensa_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		handle->syntax |= (int)value;
	}

	if (type == CS_OPT_MODE) {
		handle->mode |= (cs_mode)value;
	}

	if (type == CS_OPT_LITBASE) {
		handle->LITBASE = (uint32_t)value;
	}

	return CS_ERR_OK;
}