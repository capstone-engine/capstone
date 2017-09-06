/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#ifdef CAPSTONE_HAS_M680X

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "M680XDisassembler.h"
#include "M680XDisassemblerInternals.h"
#include "M680XInstPrinter.h"

static cs_err init(cs_struct *ud)
{
	m680x_info *info;
	cs_err errcode = CS_ERR_OK;

	info = cs_mem_malloc(sizeof(m680x_info));

	if (!info) {
		return CS_ERR_MEM;
	}

	ud->printer = M680X_printInst;
	ud->printer_info = info;
	ud->getinsn_info = NULL;
	ud->disasm = M680X_getInstruction;
	ud->skipdata_size = 1;
	ud->post_printer = NULL;

	ud->reg_name = M680X_reg_name;
	ud->insn_id = M680X_get_insn_id;
	ud->insn_name = M680X_insn_name;
	ud->group_name = M680X_group_name;

	/* Do some validation checks */
	errcode = M680X_disassembler_init(ud);

	if (errcode != CS_ERR_OK)
		return errcode;

	return M680X_instprinter_init(ud);
}

static cs_err option(cs_struct *handle, cs_opt_type type, size_t value)
{
	//TODO
	return CS_ERR_OK;
}

void M680X_enable(void)
{
	arch_init[CS_ARCH_M680X] = init;
	arch_option[CS_ARCH_M680X] = option;

	// support this arch
	all_arch |= (1 << CS_ARCH_M680X);
}

#endif

