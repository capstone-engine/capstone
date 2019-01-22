/* Capstone Disassembly Engine */
/* MOS65XX Backend by Sebastian Macke <sebastian@macke.de> 2018 */

#ifdef CAPSTONE_HAS_MOS65XX

#include "../../utils.h"
#include "../../MCRegisterInfo.h"
#include "MOS65XXDisassembler.h"
#include "MOS65XXModule.h"

cs_err MOS65XX_global_init(cs_struct *ud)
{
	// verify if requested mode is valid
	if (ud->mode)
		return CS_ERR_MODE;

	ud->printer = MOS65XX_printInst;
	ud->printer_info = NULL;
	ud->insn_id = MOS65XX_get_insn_id;
	ud->insn_name = MOS65XX_insn_name;
	ud->group_name = MOS65XX_group_name;
	ud->disasm = MOS65XX_getInstruction;
	ud->reg_name = MOS65XX_reg_name;

	return CS_ERR_OK;
}

cs_err MOS65XX_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}

#endif
