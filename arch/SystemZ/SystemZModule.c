/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SYSTEMZ

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "SystemZMapping.h"
#include "SystemZModule.h"

cs_err SystemZ_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	SystemZ_init_mri(mri);
	ud->printer = SystemZ_printer;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = SystemZ_getInstruction;
	ud->post_printer = NULL;

	ud->reg_name = SystemZ_reg_name;
	ud->insn_id = SystemZ_get_insn_id;
	ud->insn_name = SystemZ_insn_name;
	ud->group_name = SystemZ_group_name;

	return CS_ERR_OK;
}

cs_err SystemZ_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		handle->syntax = (int) value;
	} else if (type == CS_OPT_MODE) {
		handle->mode |= (cs_mode)value;
	}

	return CS_ERR_OK;
}

#endif
