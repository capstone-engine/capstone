#include "RISCVDisassembler.h"
#include "RISCVHelpers.h"

#include "RISCVDecode.gen.inc"
#include "RISCVDecodeCompressed.gen.inc"
#include "RISCVInsnMappings.gen.inc"
#include "RISCVOperands.gen.inc"
#include "../../cs_priv.h"
#include "../../utils.h"

bool riscv_get_instruction(csh handle, 
                    const uint8_t *code, size_t code_len, MCInst *instr, 
                    uint16_t *size, uint64_t address, void *info) {
    cs_insn *insn = instr->flat_insn;

    int sz = riscv_get_instruction_size(code[0]);

    RVContext ctx;
    riscv_init_riscv_context(&ctx);

    struct ast instruction;
    if (sz == 2) {
        decode_compressed(&instruction, readBytes16(instr, code), &ctx);
    } else if (sz == 4) {
        decode(&instruction, readBytes32(instr, code), &ctx);
    } else {
        printf("RISCVDisassembler.c: Invalid Size %d, RISCV Instructions Are Either 2 Or 4 Bytes\n", sz);
        return false;
    }

    // VERY HACKY: use op_str as a temporary buffer to serialize the instruction struct
    // so that the printer callback can later de-serialize it in order to stringify it
    // alternatives:
    //             (1) duplicating the decoding again in the printer
    //             (2) doing all the work including decoding in the printer (and not here)
    CS_ASSERT(sizeof(struct ast) < 160);
    memcpy(insn->op_str, &instruction, sizeof(struct ast));

    insn->id = get_insn_type(&instruction);
    insn->address = address;
    
    *size = sz;

    fill_operands(&instruction, insn->detail->riscv.operands, &(insn->detail->riscv.op_count));
    patch_operands(&instruction, insn->detail->riscv.operands, &(insn->detail->riscv.op_count), &ctx);
    return true;
}