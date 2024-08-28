/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_SYSZ_MAP_H
#define CS_SYSZ_MAP_H

#include <capstone/capstone.h>

#include "../../cs_priv.h"

// return name of register in friendly string
const char *SystemZ_reg_name(csh handle, unsigned int reg);

// given internal insn id, return public instruction info
void SystemZ_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);

const char *SystemZ_insn_name(csh handle, unsigned int id);

const char *SystemZ_group_name(csh handle, unsigned int id);

void SystemZ_printer(MCInst *MI, SStream *O, void * /* MCRegisterInfo* */ info);
bool SystemZ_getInstruction(csh handle, const uint8_t *bytes, size_t bytes_len,
			MCInst *MI, uint16_t *size, uint64_t address,
			void *info);
void SystemZ_init_mri(MCRegisterInfo *MRI);
void SystemZ_init_cs_detail(MCInst *MI);

#endif

