/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_AArch64_DISASSEMBLER_EXTENSION_H
#define CS_AArch64_DISASSEMBLER_EXTENSION_H

#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "../../cs_priv.h"
#include "AArch64AddressingModes.h"
#include "capstone/arm64.h"
#include "capstone/capstone.h"

bool AArch64_getFeatureBits(unsigned int mode, arm64_insn_group feature);
bool AArch64_testFeatureList(unsigned int mode, const arm64_insn_group *features);

bool Check(DecodeStatus *Out, DecodeStatus In);

#endif // CS_AArch64_DISASSEMBLER_EXTENSION_H
