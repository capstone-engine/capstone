/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_SYSZ

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "SystemZDisassembler.h"
#include "SystemZInstPrinter.h"
#include "SystemZMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	mri = cs_mem_malloc(sizeof(*mri));

	SystemZ_init(mri);
	ud->printer = SystemZ_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = SystemZ_getInstruction;
	ud->post_printer = SystemZ_post_printer;

	ud->reg_name = SystemZ_reg_name;
	ud->insn_id = SystemZ_get_insn_id;
	ud->insn_name = SystemZ_insn_name;
	ud->group_name = SystemZ_group_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax = (int) value;

	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void SystemZ_enable(void)
{
	arch_init[CS_ARCH_SYSZ] = init;
	arch_option[CS_ARCH_SYSZ] = option;
	arch_destroy[CS_ARCH_SYSZ] = destroy;

	// support this arch
	all_arch |= (1 << CS_ARCH_SYSZ);
}

#endif
