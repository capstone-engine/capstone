#include "RISCVPrinter.h"
#include "RISCVAst2Str.gen.inc"

void riscv_printer(MCInst *MI, SStream *OS, void *info) {
    struct ast instruction;

    RVContext ctx;
    riscv_init_riscv_context(&ctx);
    
    CS_ASSERT(sizeof(struct ast) < 160);
    memcpy(&instruction, MI->flat_insn->op_str, sizeof(struct ast));

    ast2str(&instruction, OS, &ctx);
}