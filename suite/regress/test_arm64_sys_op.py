import unittest
from capstone import *
from capstone.arm64 import *

class AArch64SysOpTest(unittest.TestCase):
    PATTERNS = [
        ("22 7b 0b d5", ARM64_DC_CVAU, ARM64_REG_X2),    # dc cvau, x2
        ("20 75 0b d5", ARM64_IC_IVAU, ARM64_REG_X0),    # ic ivau, x0
        ("c0 78 0c d5", ARM64_AT_S12E0R, ARM64_REG_X0),  # at s12e0r, x0
        ("22 87 08 d5", ARM64_TLBI_VAE1, ARM64_REG_X2),  # tlbi vae1, x2
        ("1f 83 08 d5", ARM64_TLBI_VMALLE1IS, None),     # tlbi vmalle1is
    ]

    def test_operands(self):
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True

        for pattern, sys, reg in self.PATTERNS:
            l = list(cs.disasm(bytes.fromhex(pattern), 0))
            self.assertEqual(len(l), 1)
            insn = l[0]

            if reg is None:
                op_count = 1
            else:
                op_count = 2

            self.assertEqual(len(insn.operands), op_count)
            self.assertEqual(insn.operands[0].type, ARM64_OP_SYS)
            self.assertEqual(insn.operands[0].value.sys, sys)

            if reg:
                self.assertEqual(insn.operands[1].type, ARM64_OP_REG)
                self.assertEqual(insn.operands[1].value.reg, reg)

if __name__ == '__main__':
    unittest.main()
