#ifndef CAPSTONE_CSTOOL_CSTOOL_H_
#define CAPSTONE_CSTOOL_CSTOOL_H_

void print_insn_detail_x86(csh ud, cs_mode mode, cs_insn *ins);
void print_insn_detail_arm(csh handle, cs_insn *ins);
void print_insn_detail_arm64(csh handle, cs_insn *ins);
void print_insn_detail_mips(csh handle, cs_insn *ins);
void print_insn_detail_ppc(csh handle, cs_insn *ins);
void print_insn_detail_sparc(csh handle, cs_insn *ins);
void print_insn_detail_sysz(csh handle, cs_insn *ins);
void print_insn_detail_xcore(csh handle, cs_insn *ins);
void print_insn_detail_m68k(csh handle, cs_insn *ins);
void print_insn_detail_tms320c64x(csh handle, cs_insn *ins);
void print_insn_detail_m680x(csh handle, cs_insn *ins);
void print_insn_detail_evm(csh handle, cs_insn *ins);
void print_insn_detail_riscv(csh handle, cs_insn *ins);
void print_insn_detail_wasm(csh handle, cs_insn *ins);
void print_insn_detail_mos65xx(csh handle, cs_insn *ins);
void print_insn_detail_bpf(csh handle, cs_insn *ins);
void print_insn_detail_sh(csh handle, cs_insn *ins);
void print_insn_detail_tricore(csh handle, cs_insn *ins);

#endif //CAPSTONE_CSTOOL_CSTOOL_H_
