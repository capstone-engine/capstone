# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = []
0x80,0x23,0x3c,0xd5 == mrs x0, HACDBSBR_EL2
0x80,0x23,0x1c,0xd5 == msr HACDBSBR_EL2, x0
0xa0,0x23,0x3c,0xd5 == mrs x0, HACDBSCONS_EL2
0xa0,0x23,0x1c,0xd5 == msr HACDBSCONS_EL2, x0
