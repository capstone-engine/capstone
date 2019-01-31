#ifndef FACTORY_H
#define FACTORY_H

#include <capstone/capstone.h>
#include "helper.h"

char *get_detail_arm(csh *handle, cs_insn *ins);
char *get_detail_arm64(csh *handle, cs_insn *ins);
char *get_detail_mips(csh *handle, cs_insn *ins);
char *get_detail_ppc(csh *handle, cs_insn *ins);
char *get_detail_sparc(csh *handle, cs_insn *ins);
char *get_detail_sysz(csh *handle, cs_insn *ins);
char *get_detail_x86(csh *handle, cs_insn *ins);
char *get_detail_xcore(csh *handle, cs_insn *ins);
char *get_detail_m68k(csh *handle, cs_insn *ins);

#endif /* FACTORY_H */
