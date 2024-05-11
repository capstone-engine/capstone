# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = []
0xa0,0x11,0x3e,0xd5 == mrs x0, FGWTE3_EL3
0xa0,0x11,0x1e,0xd5 == msr FGWTE3_EL3, x0
