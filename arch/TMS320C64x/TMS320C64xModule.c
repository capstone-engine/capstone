/* Capstone Disassembly Engine */
/* TMS320C64x Backend by Fotis Loukos <me@fotisl.com> 2016 */

#ifdef CAPSTONE_HAS_TMS320C64X

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "TMS320C64xDisassembler.h"
#include "TMS320C64xInstPrinter.h"
#include "TMS320C64xMapping.h"

static cs_err init(cs_struct *ud)
{
	MCRegisterInfo *mri;

	mri = cs_mem_malloc(sizeof(*mri));

	TMS320C64x_init(mri);
	ud->printer = TMS320C64x_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = TMS320C64x_getInstruction;
	ud->post_printer = TMS320C64x_post_printer;

	ud->reg_name = TMS320C64x_reg_name;
	ud->insn_id = TMS320C64x_get_insn_id;
	ud->insn_name = TMS320C64x_insn_name;
	ud->group_name = TMS320C64x_group_name;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

void TMS320C64x_enable(void)
{
	arch_init[CS_ARCH_TMS320C64X] = init;
	arch_option[CS_ARCH_TMS320C64X] = option;

	all_arch |= (1 << CS_ARCH_TMS320C64X);
}

#endif
