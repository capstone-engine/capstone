#include "RISCVDisassembler.h"
#include "RISCVDetails.h"

#include "riscv_decode.gen.inc"
#include "riscv_insn_mapping.gen.inc"
#include "riscv_ast2str.gen.inc"

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

        char instruction_as_str[RISCV_MAX_INSTRUCTION_STR_LEN];
        riscv_conf conf;
        conf.sys_enable_fdext = NULL;
        conf.sys_enable_zfinx = NULL;

        ast2str(&instruction, instruction_as_str, &conf);

        char *curr = instruction_as_str;
        uint16_t mnemonic_len = 0;
        while (*curr != ' ') {
            mnemonic_len++;
            curr++;
        }
        uint16_t operand_len = 0;
        while (*curr) {
            operand_len++;
            curr++;
        }
        memcpy(insn->mnemonic, instruction_as_str, mnemonic_len);
        memcpy(insn->op_str, instruction_as_str + mnemonic_len + 1, operand_len);
        return true;
    } else {

    }
    return false;
}