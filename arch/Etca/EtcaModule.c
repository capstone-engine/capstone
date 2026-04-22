/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#ifdef CAPSTONE_HAS_ETCA

#include "../../cs_priv.h"
#include "EtcaDisassembler.h"
#include "EtcaInstPrinter.h"
#include "EtcaModule.h"

cs_err Etca_global_init(cs_struct *ud)
{
	etca_info *info;

	info = cs_mem_calloc(1, sizeof(etca_info));
	if (!info) {
		return CS_ERR_MEM;
	}

	ud->printer = Etca_printInst;
	ud->printer_info = info;
	ud->getinsn_info = info;
	ud->reg_name = Etca_reg_name;
	ud->insn_id = Etca_get_insn_id;
	ud->insn_name = Etca_insn_name;
	ud->group_name = Etca_group_name;
	ud->disasm = Etca_getInstruction;
	ud->post_printer = NULL;
#ifndef CAPSTONE_DIET
	ud->reg_access = Etca_reg_access;
#endif

	return CS_ERR_OK;
}

cs_err Etca_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

#endif
