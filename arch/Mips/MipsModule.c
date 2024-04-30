/* Capstone Disassembly Engine */
/* By Giovanni Dante Grazioli, deroad <wargio@libero.it>, 2024 */

#ifdef CAPSTONE_HAS_MIPS

#include <capstone/capstone.h>

#include "MipsModule.h"
#include "../../MCRegisterInfo.h"
#include "../../cs_priv.h"
#include "MipsMapping.h"

cs_err Mips_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	Mips_init_mri(mri);

	ud->printer = Mips_printer;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->reg_name = Mips_reg_name;
	ud->insn_id = Mips_get_insn_id;
	ud->insn_name = Mips_insn_name;
	ud->group_name = Mips_group_name;
	ud->disasm = Mips_getInstruction;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = Mips_reg_access;
#endif

	return CS_ERR_OK;
}

cs_err Mips_option(cs_struct *handle, cs_opt_type type, size_t value)
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
