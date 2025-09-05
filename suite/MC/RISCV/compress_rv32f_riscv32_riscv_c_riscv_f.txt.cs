# CS_ARCH_RISCV, "CS_MODE_RISCV32"|"CS_MODE_RISCV_C"|"CS_MODE_RISCV_F", None
0x76,0x70 == flw ft0, 124(sp)
0x82,0xfe == fsw ft0, 124(sp)
0x60,0x7c == flw fs0, 124(s0)
0x60,0xfc == fsw fs0, 124(s0)