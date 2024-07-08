/* Capstone Disassembly Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#ifdef CAPSTONE_HAS_AARCH64

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "AArch64InstPrinter.h"
#include "AArch64Mapping.h"
#include "AArch64Module.h"

cs_err AArch64_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	AArch64_init_mri(mri);
	ud->printer = AArch64_printer;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = AArch64_getInstruction;
	ud->reg_name = AArch64_reg_name;
	ud->insn_id = AArch64_get_insn_id;
	ud->insn_name = AArch64_insn_name;
	ud->group_name = AArch64_group_name;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = AArch64_reg_access;
#endif

	return CS_ERR_OK;
}

cs_err AArch64_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax |= (int)value;

	if (type == CS_OPT_MODE) {
		handle->mode |= (cs_mode)value;
	}

	return CS_ERR_OK;
}

#endif
