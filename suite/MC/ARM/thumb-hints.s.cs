# CS_ARCH_ARM, CS_MODE_THUMB, None
0x00,0xbf = nop
0x10,0xbf = yield
0x20,0xbf = wfe
0x30,0xbf = wfi
0x40,0xbf = sev
0xbf,0xf3,0x5f,0x8f = dmb sy
0xbf,0xf3,0x5f,0x8f = dmb sy
0xbf,0xf3,0x4f,0x8f = dsb sy
0xbf,0xf3,0x4f,0x8f = dsb sy
0xbf,0xf3,0x6f,0x8f = isb sy
0xbf,0xf3,0x6f,0x8f = isb sy
