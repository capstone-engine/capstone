import unittest
from capstone import *
from capstone.arm64 import *

class AArch64SysOpTest(unittest.TestCase):
    PATTERNS = [
        "22 7b 0b d5",  # dc cvau, x2
    ]

    def test_operands(self):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True

        for pattern in self.PATTERNS:
            l = list(cs.disasm(bytes.fromhex(pattern), 0))
            self.assertEqual(len(l), 1)
            insn = l[0]

            self.assertEqual(len(insn.operands), 2)
            self.assertEqual(insn.operands[0].type, ARM64_OP_SYS)
            self.assertEqual(insn.operands[0].value.sys, ARM64_DC_CVAU)

            self.assertEqual(insn.operands[1].type, ARM64_OP_REG)
            self.assertEqual(insn.operands[1].value.reg, ARM64_REG_X2)

if __name__ == '__main__':
    unittest.main()