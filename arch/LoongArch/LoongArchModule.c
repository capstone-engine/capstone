/* Capstone Disassembly Engine */
/* By Jiajie Chen <c@jia.je> 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifdef CAPSTONE_HAS_LOONGARCH

#include <capstone/capstone.h>

#include "LoongArchModule.h"
#include "../../MCRegisterInfo.h"
#include "../../cs_priv.h"
#include "LoongArchMapping.h"

cs_err LoongArch_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	LoongArch_init_mri(mri);

	ud->printer = LoongArch_printer;
	ud->printer_info = mri;
	ud->reg_name = LoongArch_reg_name;
	ud->insn_id = LoongArch_get_insn_id;
	ud->insn_name = LoongArch_insn_name;
	ud->group_name = LoongArch_group_name;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = LoongArch_reg_access;
#endif

	ud->disasm = LoongArch_getInstruction;

	return CS_ERR_OK;
}

cs_err LoongArch_option(cs_struct *handle, cs_opt_type type, size_t value)
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
