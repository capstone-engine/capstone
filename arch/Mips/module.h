/* Capstone Disassembler Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#ifndef __MIPS_INCLUDE_H__
#define __MIPS_INCLUDE_H__

#include "MipsDisassembler.h"
#include "MipsInstPrinter.h"
#include "mapping.h"

static void init_mips(cs_struct *ud)
{
	MCRegisterInfo *mri = malloc(sizeof(*mri));

	Mips_init(mri);
	ud->printer = Mips_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->reg_name = Mips_reg_name;
	ud->insn_id = Mips_get_insn_id;
	ud->insn_name = Mips_insn_name;

	if (ud->mode & CS_MODE_32)
		ud->disasm = Mips_getInstruction;
	else
		ud->disasm = Mips64_getInstruction;
}

static cs_err option_mips(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		if (value & CS_MODE_32)
			handle->disasm = Mips_getInstruction;
		else
			handle->disasm = Mips64_getInstruction;

		handle->mode = value;
	}
	return CS_ERR_OK;
}

static void __attribute__ ((constructor)) __init_mips__()
{
	init_arch[CS_ARCH_MIPS] = init_mips;
	option_arch[CS_ARCH_MIPS] = option_mips;
}

#endif
