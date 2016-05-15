/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "TriCoreDisassembler.h"
#include "TriCoreInstPrinter.h"
#include "TriCoreMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	mri = cs_mem_malloc(sizeof(*mri));

	TriCore_init(mri);
	ud->printer = TriCore_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = TriCore_getInstruction;
	ud->post_printer = TriCore_post_printer;

	ud->reg_name = TriCore_reg_name;
	ud->insn_id = TriCore_get_insn_id;
	ud->insn_name = TriCore_insn_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void TriCore_enable(void)
{
	arch_init[CS_ARCH_TRICORE] = init;
	arch_option[CS_ARCH_TRICORE] = option;
	arch_destroy[CS_ARCH_TRICORE] = destroy;

	// support this arch
	all_arch |= (1 << CS_ARCH_TRICORE);
}

#endif
