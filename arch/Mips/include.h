#ifndef __MIPS_INCLUDE_H__
#define __MIPS_INCLUDE_H__

#include "MipsDisassembler.h"
#include "MipsInstPrinter.h"
#include "mapping.h"

void init_mips(cs_struct *ud) {
  MCRegisterInfo *mri = malloc(sizeof(*mri));

  Mips_init(mri);
  ud->printer = Mips_printInst;
  ud->printer_info = mri;
  ud->getinsn_info = mri;
  ud->reg_name = Mips_reg_name;
  ud->insn_id = Mips_get_insn_id;
  ud->insn_name = Mips_insn_name;

  if (ud->mode & CS_MODE_32)
    ud->disasm = Mips_getInstruction;
  else
    ud->disasm = Mips64_getInstruction;
}

void __attribute__ ((constructor)) __init_mips__() {
  init_arch[CS_ARCH_MIPS] = init_mips;
}

#endif
