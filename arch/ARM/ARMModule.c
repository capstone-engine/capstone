/* Capstone Disassembly Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#include "capstone/capstone.h"
#ifdef CAPSTONE_HAS_ARM

#include "ARMModule.h"
#include "../../MCRegisterInfo.h"
#include "../../cs_priv.h"
#include "ARMInstPrinter.h"
#include "ARMMapping.h"

cs_err ARM_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	ARM_init_mri(mri);

	ud->printer = ARM_printer;
	ud->printer_info = mri;
	ud->reg_name = ARM_reg_name;
	ud->insn_id = ARM_get_insn_id;
	ud->insn_name = ARM_insn_name;
	ud->group_name = ARM_group_name;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = ARM_reg_access;
#endif

	ud->disasm = ARM_getInstruction;

	return CS_ERR_OK;
}

cs_err ARM_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	switch (type) {
	case CS_OPT_MODE:
		handle->mode |= (cs_mode)value;
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
