#include "RISCVPrinter.h"
#include "RISCVAst2Str.gen.inc"

void riscv_printer(MCInst *MI, SStream *OS, void *info) {
    struct ast instruction;

    riscv_conf conf;
    conf.sys_enable_fdext = NULL;
    conf.sys_enable_zfinx = NULL;
    
    CS_ASSERT(sizeof(struct ast) < 160);
    memcpy(&instruction, MI->flat_insn->op_str, sizeof(struct ast));

    ast2str(&instruction, OS, &conf);
}