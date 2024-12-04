/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2024 */

#ifdef CAPSTONE_HAS_ARC

#include <capstone/capstone.h>

#include "ARCModule.h"
#include "../../MCRegisterInfo.h"
#include "../../cs_priv.h"
#include "ARCMapping.h"

cs_err ARC_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	ARC_init_mri(mri);

	ud->printer = ARC_printer;
	ud->printer_info = mri;
	ud->reg_name = ARC_reg_name;
	ud->insn_id = ARC_get_insn_id;
	ud->insn_name = ARC_insn_name;
	ud->group_name = ARC_group_name;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = ARC_reg_access;
#endif

	ud->disasm = ARC_getInstruction;

	return CS_ERR_OK;
}

cs_err ARC_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	switch (type) {
	case CS_OPT_MODE:
		handle->mode = (cs_mode)value;
		break;
	case CS_OPT_SYNTAX:
		handle->syntax |= (int)value;
		break;
	default:
		break;
	}

	return CS_ERR_OK;
}

#endif