#include "RISCVDetails.h"

/*
The size calculation algorithm according to the RISCV spec:
    1- Check the first (least-significant) 2 bits...
        1.1- If they're not 11, then the instruction is a 16-bits instruction.
        
    2- Otherwise, if they're 11, Check the next 3 bits (3rd-5th)...
        2.1- If they're not 111, then the instruction is a 32-bits instruction.

    3- Otherwise, if they're 111, check the next (6th) bit...
        3.1- If it's not 1, then the instruction is a 48-bits instruction.

    4- Otherwise, if it's 1, check the next (7th) bit...
        4.1- If it's not 1, then the instruction is 1 64-bits instruction.

    5- Otherwise, the instruction size can be determined from other bits further from the first byte.

    (The spec actually specifies valid sizes up to 192-bits instructions, even reserving a pattern for
     instructions beyond 192 bits. In practice, even 48-bits or 64-bits instructions are extremly rare,
     and it's not worth complicating the code with a bitvector type to represent bigger instructions.)
*/
int riscv_get_instruction_size(uint8_t first_byte) {
    if ((first_byte & 0x3) != 0x3) {
        return 2;
    } else if (((first_byte >> 2) & 0x7) != 0x7) {
        return 4;
    } else if (((first_byte >> 5) & 0x1) == 0x0) {
        return 6;
    } else if (((first_byte >> 6) & 0x1) == 0x0) {
        return 8;
    } else {
        return 0;
    }
}