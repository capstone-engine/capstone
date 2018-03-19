/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_XCORE

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "XCoreDisassembler.h"
#include "XCoreInstPrinter.h"
#include "XCoreMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	XCore_init(mri);
	ud->printer = XCore_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = XCore_getInstruction;
	ud->post_printer = XCore_post_printer;

	ud->reg_name = XCore_reg_name;
	ud->insn_id = XCore_get_insn_id;
	ud->insn_name = XCore_insn_name;
	ud->group_name = XCore_group_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	// Do not set mode because only CS_MODE_BIG_ENDIAN is valid; we cannot
	// test for CS_MODE_LITTLE_ENDIAN because it is 0

	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void XCore_enable(void)
{
	cs_arch_init[CS_ARCH_XCORE] = init;
	cs_arch_option[CS_ARCH_XCORE] = option;
	cs_arch_destroy[CS_ARCH_XCORE] = destroy;
	cs_arch_disallowed_mode_mask[CS_ARCH_XCORE] = ~CS_MODE_BIG_ENDIAN;

	// support this arch
	all_arch |= (1 << CS_ARCH_XCORE);
}

#endif
