import unittest
from capstone import *
from capstone.x86 import *
from capstone.arm64 import *

class SubRegTest(unittest.TestCase):

    def test_x86(self):
        cs = Cs(CS_ARCH_X86, CS_MODE_64)

        # GP registers
        self.assertTrue(cs.reg_is_subreg(X86_REG_RAX, X86_REG_AL))
        self.assertTrue(cs.reg_is_subreg(X86_REG_RAX, X86_REG_AH))
        self.assertTrue(cs.reg_is_subreg(X86_REG_RAX, X86_REG_EAX))

        self.assertTrue(cs.reg_is_subreg(X86_REG_EAX, X86_REG_AL))
        self.assertTrue(cs.reg_is_subreg(X86_REG_EAX, X86_REG_AH))

        self.assertFalse(cs.reg_is_subreg(X86_REG_RBX, X86_REG_DH))

        self.assertTrue(cs.reg_is_subreg(X86_REG_R10, X86_REG_R10B))
        self.assertTrue(cs.reg_is_subreg(X86_REG_R10, X86_REG_R10W))
        self.assertTrue(cs.reg_is_subreg(X86_REG_R10, X86_REG_R10D))
        self.assertTrue(cs.reg_is_subreg(X86_REG_R10W, X86_REG_R10B))
        self.assertTrue(cs.reg_is_subreg(X86_REG_R10D, X86_REG_R10W))

        # XMM regs
        self.assertTrue(cs.reg_is_subreg(X86_REG_YMM0, X86_REG_XMM0))
        self.assertTrue(cs.reg_is_subreg(X86_REG_ZMM0, X86_REG_YMM0))
        self.assertTrue(cs.reg_is_subreg(X86_REG_ZMM0, X86_REG_XMM0))

        self.assertFalse(cs.reg_is_subreg(X86_REG_YMM0, X86_REG_XMM1))

    def test_arm64(self):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

        # GP registers
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_X0, ARM64_REG_W0))
        self.assertFalse(cs.reg_is_subreg(ARM64_REG_X0, ARM64_REG_X0))
        self.assertFalse(cs.reg_is_subreg(ARM64_REG_X1, ARM64_REG_W2))

        # NEON registers
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_Q0, ARM64_REG_B0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_Q0, ARM64_REG_H0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_Q0, ARM64_REG_S0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_Q0, ARM64_REG_D0))

        self.assertTrue(cs.reg_is_subreg(ARM64_REG_D0, ARM64_REG_B0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_D0, ARM64_REG_H0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_D0, ARM64_REG_S0))

        self.assertTrue(cs.reg_is_subreg(ARM64_REG_S0, ARM64_REG_B0))
        self.assertTrue(cs.reg_is_subreg(ARM64_REG_S0, ARM64_REG_H0))

        self.assertTrue(cs.reg_is_subreg(ARM64_REG_H0, ARM64_REG_B0))

        self.assertFalse(cs.reg_is_subreg(ARM64_REG_H2, ARM64_REG_B3))

if __name__ == '__main__':
    unittest.main()
