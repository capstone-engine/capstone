/* Capstone Disassembly Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#ifdef CAPSTONE_HAS_ARM64

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "AArch64Disassembler.h"
#include "AArch64InstPrinter.h"
#include "AArch64Mapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	// verify if requested mode is valid
	if (ud->mode & ~(CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM | CS_MODE_BIG_ENDIAN))
		return CS_ERR_MODE;

	mri = cs_mem_malloc(sizeof(*mri));

	AArch64_init(mri);
	ud->printer = AArch64_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = AArch64_getInstruction;
	ud->reg_name = AArch64_reg_name;
	ud->insn_id = AArch64_get_insn_id;
	ud->insn_name = AArch64_insn_name;
	ud->group_name = AArch64_group_name;
	ud->post_printer = AArch64_post_printer;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE) {
		handle->big_endian = (((cs_mode)value & CS_MODE_BIG_ENDIAN) != 0);
	}

	return CS_ERR_OK;
}

static void destroy(cs_struct *handle)
{
}

void AArch64_enable(void)
{
	arch_init[CS_ARCH_ARM64] = init;
	arch_option[CS_ARCH_ARM64] = option;
	arch_destroy[CS_ARCH_ARM64] = destroy;

	// support this arch
	all_arch |= (1 << CS_ARCH_ARM64);
}

#endif
