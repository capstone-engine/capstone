/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPAMAPPING_H
#define CS_HPPAMAPPING_H

#include <capstone/capstone.h>

#include "../../cs_priv.h"

const char *HPPA_group_name(csh handle, unsigned int id);
const char *HPPA_insn_name(csh handle, unsigned int id);
const char *HPPA_reg_name(csh handle, unsigned int reg);
void HPPA_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
void HPPA_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count);

#endif