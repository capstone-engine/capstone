/* Capstone Disassembly Engine */
/* RISC-V Backend By Rodrigo Cortes Porto <porto703@gmail.com> & 
   Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */

#ifdef CAPSTONE_HAS_RISCV

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "RISCVInstPrinter.h"
#include "RISCVMapping.h"
#include "RISCVModule.h"
#include "RISCVLinkage.h"

cs_err RISCV_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));
	if (!mri)
		return CS_ERR_MEM;

	RISCV_init(mri);
	ud->printer = RISCV_LLVM_printInstruction;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = RISCV_LLVM_getInstruction;
	ud->post_printer = NULL;

	ud->reg_name = RISCV_reg_name;
	ud->insn_id = RISCV_get_insn_id;
	ud->insn_name = RISCV_insn_name;
	ud->group_name = RISCV_group_name;
	ud->insn_map = RISCV_insns;
	ud->insn_map_size = RISCV_insn_count;

	return CS_ERR_OK;
}

cs_err RISCV_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX) {
		handle->syntax = (int)value;
	} else if (type == CS_OPT_MODE) {
		handle->mode = (cs_mode)value;
	}

	return CS_ERR_OK;
}

#endif
