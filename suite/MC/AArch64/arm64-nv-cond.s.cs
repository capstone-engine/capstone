# CS_ARCH_ARM64, 0, None
0xfc,0xff,0x7f,0x1e = fcsel d28, d31, d31, nv
0x00,0xf0,0x80,0x9a = csel x0, x0, x0, nv
0x00,0xf0,0x40,0xfa = ccmp x0, x0, #0, nv
0x0f,0x00,0x00,0x54 = b.nv #0
