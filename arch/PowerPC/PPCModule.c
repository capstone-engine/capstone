/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_POWERPC

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "PPCMapping.h"
#include "PPCModule.h"

cs_err PPC_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = (MCRegisterInfo *)cs_mem_malloc(sizeof(*mri));

	PPC_init_mri(mri);
	ud->printer = PPC_printer;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = PPC_getInstruction;
	ud->post_printer = NULL;

	ud->reg_name = PPC_reg_name;
	ud->insn_id = PPC_get_insn_id;
	ud->insn_name = PPC_insn_name;
	ud->group_name = PPC_group_name;

	return CS_ERR_OK;
}

cs_err PPC_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax = (int)value;

	if (type == CS_OPT_MODE) {
		if (value == CS_MODE_LITTLE_ENDIAN) {
			handle->mode = handle->mode & ~CS_MODE_BIG_ENDIAN;
			return CS_ERR_OK;
		}
		handle->mode |= (cs_mode)value;
		if (value & CS_MODE_MSYNC) {
			handle->mode |= (cs_mode)CS_MODE_BOOKE;
		}
	}

	return CS_ERR_OK;
}

#endif
