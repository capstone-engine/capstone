# CS_ARCH_AARCH64, None, None
# This regression test file is new. The option flags could not be determined.
# LLVM uses the following mattr = ['mattr=+ssbs', 'mattr=+v8.5a', 'mattr=+v8r', 'mattr=-ssbs']
0x3f 0x41 0x03 0xd5 == msr SSBS, #1
0xc3 0x42 0x1b 0xd5 == msr SSBS, x3
0xc2 0x42 0x3b 0xd5 == mrs x2, SSBS
