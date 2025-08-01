# CS_ARCH_RISCV, 0, None
0x2e,0x95 == .insn cr 2, 9, a0, a1
0x35,0x05 == .insn ci 1, 0, a0, 13
0xa8,0x01 == .insn ciw 0, 0, a0, 13
0xaa,0xc6 == .insn css 2, 6, a0, 13
0xa8,0x4d == .insn cl 0, 2, a0, 13(a1)
0xa8,0xcd == .insn cs 0, 6, a0, 13(a1)
0x0d,0x8d == .insn ca 1, 35, 0, a0, a1
0x01 == .insn cb 1, 6, a0, target