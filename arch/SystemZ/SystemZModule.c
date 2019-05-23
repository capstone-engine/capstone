/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_SYSZ

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "SystemZDisassembler.h"
#include "SystemZInstPrinter.h"
#include "SystemZMapping.h"
#include "SystemZModule.h"

static size_t CAPSTONE_API default_skipdata_cb(const uint8_t *code,
					       size_t code_size,
					       size_t offset, void *user_data)
{
	// The length of any instruction is encoded in the top two bits.
	switch (code[offset] >> 6) {
	case 0:
		return 2;
	default:
		return 4;
	case 3:
		return 6;
	}
}

cs_err SystemZ_global_init(cs_struct *ud)
{
	MCRegisterInfo *mri;
	mri = cs_mem_malloc(sizeof(*mri));

	SystemZ_init(mri);
	ud->printer = SystemZ_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = SystemZ_getInstruction;
	ud->post_printer = SystemZ_post_printer;

	ud->reg_name = SystemZ_reg_name;
	ud->insn_id = SystemZ_get_insn_id;
	ud->insn_name = SystemZ_insn_name;
	ud->group_name = SystemZ_group_name;
	ud->skipdata_setup.callback = default_skipdata_cb;

	return CS_ERR_OK;
}

cs_err SystemZ_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_SYNTAX)
		handle->syntax = (int) value;

	// Do not set mode because only CS_MODE_BIG_ENDIAN is valid; we cannot
	// test for CS_MODE_LITTLE_ENDIAN because it is 0

	return CS_ERR_OK;
}

#endif
