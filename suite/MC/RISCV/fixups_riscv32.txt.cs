# CS_ARCH_RISCV, 0, None
0x23 == sw a0, %lo(val)(t1)
0x23 == sw t1, %pcrel_lo(.Ltmp0)(t1)
0x63 == beq a0, a1, .LBB0
0x63 == blt a0, a1, .LBB1
0x13,0x00,0x00,0x00 == addi zero, zero, 0
0x97 == call func