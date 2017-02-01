/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_SPARC

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "SparcDisassembler.h"
#include "SparcInstPrinter.h"
#include "SparcMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	// verify if requested mode is valid
	if (ud->mode & ~(CS_MODE_BIG_ENDIAN | CS_MODE_V9))
		return CS_ERR_MODE;

	mri = cs_mem_malloc(sizeof(*mri));

	Sparc_init(mri);
	ud->printer = Sparc_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = Sparc_getInstruction;
	ud->post_printer = Sparc_post_printer;

	ud->reg_name = Sparc_reg_name;
	ud->insn_id = Sparc_get_insn_id;
	ud->insn_name = Sparc_insn_name;
	ud->group_name = Sparc_group_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax = (int) value;

	if (type == CS_OPT_MODE) {
		handle->big_endian = (((cs_mode)value & CS_MODE_BIG_ENDIAN) != 0);
	}

	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void Sparc_enable(void)
{
	arch_init[CS_ARCH_SPARC] = init;
	arch_option[CS_ARCH_SPARC] = option;
	arch_destroy[CS_ARCH_SPARC] = destroy;

	// support this arch
	all_arch |= (1 << CS_ARCH_SPARC);
}

#endif
