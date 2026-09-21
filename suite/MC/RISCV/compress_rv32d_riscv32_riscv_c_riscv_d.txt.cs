# CS_ARCH_RISCV, "CS_MODE_RISCV32"|"CS_MODE_RISCV_C"|"CS_MODE_RISCV_D", None
0x06,0x20 == fld ft0, 64(sp)
0x82,0xa0 == fsd ft0, 64(sp)
0x60,0x3c == fld fs0, 248(s0)
0x60,0xbc == fsd fs0, 248(s0)