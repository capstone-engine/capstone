/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#ifndef FACTORY_H
#define FACTORY_H

#include <capstone/capstone.h>
#include "helper.h"

char *get_detail_evm(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_arm(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_arm64(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_m680x(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_mips(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_ppc(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_sparc(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_sysz(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_x86(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_xcore(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_m68k(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_mos65xx(csh *handle, cs_mode mode, cs_insn *ins);
char *get_detail_tms320c64x(csh *handle, cs_mode mode, cs_insn *ins);

#endif /* FACTORY_H */
