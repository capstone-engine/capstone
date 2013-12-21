/* Capstone Disassembler Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#ifndef __ARM_INCLUDE_H__
#define __ARM_INCLUDE_H__

#include "ARMDisassembler.h"
#include "ARMInstPrinter.h"
#include "mapping.h"

static void init_arm(cs_struct *ud)
{
	MCRegisterInfo *mri = malloc(sizeof(*mri));

	ARM_init(mri);

	ud->printer = ARM_printInst;
	ud->printer_info = mri;
	ud->reg_name = ARM_reg_name;
	ud->insn_id = ARM_get_insn_id;
	ud->insn_name = ARM_insn_name;
	ud->post_printer = ARM_post_printer;

	if (ud->mode & CS_MODE_THUMB)
		ud->disasm = Thumb_getInstruction;
	else
		ud->disasm = ARM_getInstruction;
}

static cs_err option_arm(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		if (value & CS_MODE_THUMB)
			handle->disasm = Thumb_getInstruction;
		else
			handle->disasm = ARM_getInstruction;

		handle->mode = value;
	}
	return CS_ERR_OK;
}

static void __attribute__ ((constructor)) __init_arm__()
{
	init_arch[CS_ARCH_ARM] = init_arm;
	option_arch[CS_ARCH_ARM] = option_arm;
}

#endif
