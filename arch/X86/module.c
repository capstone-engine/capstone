/* Capstone Disassembler Engine */
/* By Dang Hoang Vu <danghvu@gmail.com> 2013 */

#include "../../cs_priv.h"
#include "../../MCRegisterInfo.h"
#include "X86Disassembler.h"
#include "X86InstPrinter.h"
#include "mapping.h"

static cs_err init(cs_struct *ud)
{
	// by default, we use Intel syntax
	ud->printer = X86_Intel_printInst;
	ud->printer_info = NULL;
	ud->disasm = X86_getInstruction;
	ud->reg_name = X86_reg_name;
	ud->insn_id = X86_get_insn_id;
	ud->insn_name = X86_insn_name;
	ud->post_printer = X86_post_printer;

	return CS_ERR_OK;
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		switch(value) {
			default:
				// wrong syntax value
				handle->errnum = CS_ERR_OPTION;
				return CS_ERR_OPTION;

			case CS_OPT_SYNTAX_INTEL:
				handle->printer = X86_Intel_printInst;
				break;

			case CS_OPT_SYNTAX_ATT:
				handle->printer = X86_ATT_printInst;
				break;
		}
	}
	return CS_ERR_OK;
}

static void __attribute__ ((constructor)) __init_x86__()
{
	arch_init[CS_ARCH_X86] = init;
	arch_option[CS_ARCH_X86] = option;

	// support this arch
	all_arch |= (1 << CS_ARCH_X86);
}
