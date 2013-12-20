/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, Dang Hoang Vu <danghvu@gmail.com> 2013 */

#ifndef __ARM64_INCLUDE_H__
#define __ARM64_INCLUDE_H__

#include "AArch64Disassembler.h"
#include "AArch64InstPrinter.h"
#include "mapping.h"

void init_arm64(cs_struct *ud)
{
	MCRegisterInfo *mri = malloc(sizeof(*mri));

	AArch64_init(mri);
	ud->printer = AArch64_printInst;
	ud->printer_info = mri;
	ud->getinsn_info = mri;
	ud->disasm = AArch64_getInstruction;
	ud->reg_name = AArch64_reg_name;
	ud->insn_id = AArch64_get_insn_id;
	ud->insn_name = AArch64_insn_name;
	ud->post_printer = AArch64_post_printer;
}

void __attribute__ ((constructor)) __init_arm64__()
{
	init_arch[CS_ARCH_ARM64] = init_arm64;
}

#endif
