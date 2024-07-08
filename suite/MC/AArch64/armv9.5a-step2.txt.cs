# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = []
0x40,0x05,0x30,0xd5 == mrs x0, MDSTEPOP_EL1
0x40,0x05,0x10,0xd5 == msr MDSTEPOP_EL1, x0
