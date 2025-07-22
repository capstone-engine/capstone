/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "AlphaDisassembler.h"
#include "AlphaMapping.h"
#include "AlphaModule.h"

cs_err ALPHA_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	mri = cs_mem_malloc(sizeof(*mri));

	Alpha_init(mri);
	ud->printer = Alpha_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = Alpha_getInstruction;
	ud->post_printer = NULL;

	ud->reg_name = Alpha_getRegisterName;
	ud->insn_id = Alpha_get_insn_id;
	ud->insn_name = Alpha_insn_name;
	ud->group_name = Alpha_group_name;
#ifndef CAPSTONE_DIET
	ud->reg_access = Alpha_reg_access;
#endif

	return CS_ERR_OK;
}

cs_err ALPHA_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		handle->syntax = (int)value;
	} else if (type == CS_OPT_MODE) {
		handle->mode = (cs_mode)value;
	}

	return CS_ERR_OK;
}

#endif
