#include "../../include/capstone/capstone.h"
#include "../../MCInst.h"


bool riscv_get_instruction(csh handle, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *info);