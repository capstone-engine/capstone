#include "RISCVDisassembler.h"
#include "RISCVDetails.h"

#include "riscv_decode.gen.inc"
#include "riscv_insn_mapping.gen.inc"

bool riscv_get_instruction(csh handle, 
                    const uint8_t *code, size_t code_len, MCInst *instr, 
                    uint16_t *size, uint64_t address, void *info) {
    cs_insn *insn = instr->flat_insn;

    if (!riscv_fill_size(insn, code[0])) {
        return false;
    }
    // TODO: add compressed 2-bytes instructions
    if (insn->size == 2) {

    } else if (insn->size == 4) {
        struct ast instruction;
        decode(&instruction, code[3] << 24 | code[2] << 16 | code[1] << 8 | code[0]);

        insn->id = get_insn_type(&instruction);
        insn->address = address;
        *size = insn->size;
        memcpy(insn->bytes, code, insn->size);
        return true;
    } else {

    }
    return false;
}