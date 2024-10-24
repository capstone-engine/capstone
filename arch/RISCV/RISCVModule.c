/* Capstone Disassembly Engine */
/* RISC-V Backend By Rodrigo Cortes Porto <porto703@gmail.com> & 
   Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */

#ifdef CAPSTONE_HAS_RISCV

#include "RISCVModule.h"

void noop_printer(MCInst *MI, SStream *OS, void *info) {

}

void noop_postprinter(csh handle, cs_insn *, SStream *mnem, MCInst *mci) {

}

const char *noop_getname(csh handle, unsigned int id) { 
	return ""; 
}

void noop_getid(cs_struct *h, cs_insn *insn, unsigned int id) {

}

cs_err RISCV_global_init(cs_struct * ud)
{
	ud->printer = noop_printer;
	ud->printer_info = NULL;
	ud->getinsn_info = NULL;
	ud->disasm = riscv_get_instruction;
	ud->post_printer = noop_postprinter;

	ud->reg_name = noop_getname;
	ud->insn_id = noop_getid;
	ud->insn_name = noop_getname;
	ud->group_name = noop_getname;

	return CS_ERR_OK;
}

cs_err RISCV_option(cs_struct * handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		handle->syntax = (int)value;
	} else if (type == CS_OPT_MODE) {
		handle->mode = (cs_mode)value;
	}

	return CS_ERR_OK;
}

#endif
