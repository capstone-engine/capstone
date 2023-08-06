/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_ALPHADISASSEMBLER_H
#define CS_ALPHADISASSEMBLER_H

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "../../MCDisassembler.h"
#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include <capstone/capstone.h>

void Alpha_init(MCRegisterInfo *MRI);

#endif // CS_ALPHADISASSEMBLER_H