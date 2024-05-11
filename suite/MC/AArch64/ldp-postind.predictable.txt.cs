# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = ['mattr=+fp-armv8']
0xe3 0x0f 0x80 0xa8 == stp x3, x3, [sp], #0
0xa5 0x98 0xc1 0x6c == ldp d5, d6, [x5], #24
0xff 0xff 0x80 0xa8 == stp xzr, xzr, [sp], #8
