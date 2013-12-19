#ifndef __X86_INCLUDE_H__
#define __X86_INCLUDE_H__

#include "X86Disassembler.h"
#include "X86InstPrinter.h"
#include "mapping.h"

void init_x86(cs_struct *ud) {
  // by default, we use Intel syntax
  ud->printer = X86_Intel_printInst;
  ud->printer_info = NULL;
  ud->disasm = X86_getInstruction;
  ud->reg_name = X86_reg_name;
  ud->insn_id = X86_get_insn_id;
  ud->insn_name = X86_insn_name;
  ud->post_printer = X86_post_printer;
}

void __attribute__ ((constructor)) __init_x86__() {
  init_arch[CS_ARCH_X86] = init_x86;
}

#endif
