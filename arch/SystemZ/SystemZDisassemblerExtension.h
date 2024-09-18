/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H
#define CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H

#include <capstone/capstone.h>

bool SystemZ_getFeatureBits(unsigned int mode, unsigned int feature);

#endif // CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H
