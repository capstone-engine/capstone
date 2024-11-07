#include "RISCVPrinter.h"

void riscv_printer(MCInst *MI, SStream *OS, void *info) {
    // FIXME: add the ast struct as a member in the riscv_details
    //( stringification can't happen unless ast is available)

    // char instruction_as_str[RISCV_MAX_INSTRUCTION_STR_LEN];
    // riscv_conf conf;
    // conf.sys_enable_fdext = NULL;
    // conf.sys_enable_zfinx = NULL;
    // ast2str(&instruction, instruction_as_str, &conf);
}