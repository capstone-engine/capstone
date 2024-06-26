/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */
/*    Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#ifndef CS_LOONGARCH_DISASSEMBLER_EXTENSION_H
#define CS_LOONGARCH_DISASSEMBLER_EXTENSION_H

#include "capstone/capstone.h"

bool LoongArch_getFeatureBits(unsigned int mode, unsigned int feature);

#endif // CS_LOONGARCH_DISASSEMBLER_EXTENSION_H
