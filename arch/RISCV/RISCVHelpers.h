#include "../include/capstone/capstone.h"
#include "RISCVRVContextHelpers.h"

int riscv_get_instruction_size(uint8_t first_byte);

void riscv_init_riscv_context(RVContext *ctx);