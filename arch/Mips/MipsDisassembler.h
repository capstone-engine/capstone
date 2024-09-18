/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_MIPSDISASSEMBLER_H
#define CS_MIPSDISASSEMBLER_H

#include "capstone/capstone.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"

void Mips_init(MCRegisterInfo *MRI);

bool Mips_getFeatureBits(unsigned int mode, unsigned int feature);

#endif
