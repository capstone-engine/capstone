import unittest
from capstone import *
from capstone.arm64 import *

class AArch64VasSpecifierTest(unittest.TestCase):

    PATTERNS = [
        ("40 1e b2 4e", ARM64_VAS_16B), # mov v0.16b, v18.16b"
        ("40 1e b2 0e", ARM64_VAS_8B),  # mov v0.8b, v18.8b"
        ("40 5a 20 6e", ARM64_VAS_16B), # mvn v0.16b, v18.16b"
        ("40 5a 20 2e", ARM64_VAS_8B),  # mvn v0.8b, v18.8b"
    ]

    def test_vas_specifier(self):
        insts = []
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True

        for pattern, vas in self.PATTERNS:
            l = list(cs.disasm(bytes.fromhex(pattern), 0))
            self.assertEqual(len(l), 1)
            insn = l[0]

            self.assertEqual(len(insn.operands), 2)
            self.assertEqual(insn.operands[0].type, ARM64_OP_REG)
            self.assertEqual(insn.operands[0].value.reg, ARM64_REG_V0)
            self.assertEqual(insn.operands[0].vas, vas)

            self.assertEqual(insn.operands[1].type, ARM64_OP_REG)
            self.assertEqual(insn.operands[1].value.reg, ARM64_REG_V18)
            self.assertEqual(insn.operands[1].vas, vas)

if __name__ == '__main__':
    unittest.main()
