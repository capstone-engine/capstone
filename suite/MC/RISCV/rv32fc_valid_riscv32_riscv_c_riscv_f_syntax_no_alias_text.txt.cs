# CS_ARCH_RISCV, "CS_MODE_RISCV32"|"CS_MODE_RISCV_C"|"CS_MODE_RISCV_F", None
0x7e,0x74 == c.flwsp fs0, 252(sp)
0xc6,0xff == c.fswsp fa7, 252(sp)
0xf4,0x7f == c.flw fa3, 124(a5)
0xf0,0xfd == c.fsw fa2, 124(a1)