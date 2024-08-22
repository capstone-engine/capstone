# CS_ARCH_AARCH64, 0, None

0x51, == add    x17, x18, :dtprel_hi12:var, lsl #12
0x93, == add    w19, w20, :dtprel_hi12:var, lsl #12
0xd5, == add    x21, x22, :dtprel_lo12:var
0x17, == add    w23, w24, :dtprel_lo12:var
0x59, == add    x25, x26, :dtprel_lo12_nc:var
0x9b, == add    w27, w28, :dtprel_lo12_nc:var
0xdd, == ldrb    w29, [x30, :dtprel_lo12:var]
0x9d, == ldrsb    x29, [x28, :dtprel_lo12_nc:var]
0x5b, == strh    w27, [x26, :dtprel_lo12:var]
0x19, == ldrsh    x25, [x24, :dtprel_lo12_nc:var]
0xd7, == ldr    w23, [x22, :dtprel_lo12:var]
0x95, == ldrsw    x21, [x20, :dtprel_lo12_nc:var]
0x53, == ldr    x19, [x18, :dtprel_lo12:var]
0x11, == str    x17, [x16, :dtprel_lo12_nc:var]
0x0b == adrp    x11, :gottprel:var
0x0a, == ldr    x10, [x0, :gottprel_lo12:var]
0x51, == add    x17, x18, :tprel_hi12:var, lsl #12
0x93, == add    w19, w20, :tprel_hi12:var, lsl #12
0xd5, == add    x21, x22, :tprel_lo12:var
0x17, == add    w23, w24, :tprel_lo12:var
0x59, == add    x25, x26, :tprel_lo12_nc:var
0x9b, == add    w27, w28, :tprel_lo12_nc:var
0xdd, == ldrb    w29, [x30, :tprel_lo12:var]
0x9d, == ldrsb    x29, [x28, :tprel_lo12_nc:var]
0x5b, == strh    w27, [x26, :tprel_lo12:var]
0x19, == ldrsh    x25, [x24, :tprel_lo12_nc:var]
0xd7, == ldr    w23, [x22, :tprel_lo12:var]
0x95, == ldrsw    x21, [x20, :tprel_lo12_nc:var]
0x53, == ldr    x19, [x18, :tprel_lo12:var]
0x11, == str    x17, [x16, :tprel_lo12_nc:var]
0x08 == adrp    x8, :tlsdesc:var
0xc7, == ldr    x7, [x6, :tlsdesc_lo12:var]
0x85, == add    x5, x4, :tlsdesc_lo12:var
0x60,0x00,0x3f,0xd6 == blr    x3
