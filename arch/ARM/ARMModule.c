/* Capstone Disassembler Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#include "../../cs_priv.h"
#include "../../MCRegisterInfo.h"
#include "ARMDisassembler.h"
#include "ARMInstPrinter.h"
#include "ARMMapping.h"

static cs_err init(cs_struct *ud)
{
	// verify if requested mode is valid
	if (ud->mode & ~(CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM |
				CS_MODE_THUMB | CS_MODE_BIG_ENDIAN))
		return CS_ERR_MODE;

	MCRegisterInfo *mri = cs_mem_malloc(sizeof(*mri));

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

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
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

static void destroy(cs_struct *handle)
{
}

void ARM_enable(void)
{
	arch_init[CS_ARCH_ARM] = init;
	arch_option[CS_ARCH_ARM] = option;
	arch_destroy[CS_ARCH_ARM] = destroy;

	// support this arch
	all_arch |= (1 << CS_ARCH_ARM);
}
