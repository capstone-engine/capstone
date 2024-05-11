# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = []
0x40,0x23,0x3c,0xd5 == mrs x0, HDBSSBR_EL2
0x40,0x23,0x1c,0xd5 == msr HDBSSBR_EL2, x0
0x60,0x23,0x3c,0xd5 == mrs x0, HDBSSPROD_EL2
0x60,0x23,0x1c,0xd5 == msr HDBSSPROD_EL2, x0
