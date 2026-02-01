# CS_ARCH_RISCV, "CS_MODE_RISCV32"|"CS_MODE_RISCV_C"|"CS_MODE_RISCV_D", None
0x7e,0x34 == c.fldsp fs0, 504(sp)
0xc6,0xbf == c.fsdsp fa7, 504(sp)
0xf4,0x3f == c.fld fa3, 248(a5)
0xf0,0xbd == c.fsd fa2, 248(a1)