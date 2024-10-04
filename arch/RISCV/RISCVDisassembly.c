#include "RISCVDisassembly.h"
#include "RISCVDetails.h"

bool riscv_get_instruction(csh handle, 
                    const uint8_t *code, size_t code_len, MCInst *instr, 
                    uint16_t *size, uint64_t address, void *info) {
    cs_insn *insn = instr->flat_insn;

    if (!riscv_fill_size(insn, code[0])) {
        return false;
    }

    insn->address = address;
    insn->bytes = 
}