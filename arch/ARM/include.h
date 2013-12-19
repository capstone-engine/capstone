#ifndef __ARM_INCLUDE_H__
#define __ARM_INCLUDE_H__

#include "ARMDisassembler.h"
#include "ARMInstPrinter.h"
#include "mapping.h"

void init_arm(cs_struct *ud) {
  MCRegisterInfo *mri = malloc(sizeof(*mri));

  ARM_init(mri);

  ud->printer = ARM_printInst;
  ud->printer_info = mri;
  ud->reg_name = ARM_reg_name;
  ud->insn_id = ARM_get_insn_id;
  ud->insn_name = ARM_insn_name;
  ud->post_printer = ARM_post_printer;

  if (ud->mode & CS_MODE_THUMB)
    ud->disasm = Thumb_getInstruction;
  else
    ud->disasm = ARM_getInstruction;
}

void __attribute__ ((constructor)) __init_arm__() {
  init_arch[CS_ARCH_ARM] = init_arm;
}

#endif
