import unittest
from capstone import *
from capstone.arm64 import *

# By Stevie Lavern <stevie.lavern@gmail.com>, 2023.
class ARM64MovRegAccessTest(unittest.TestCase):
    # These instructions should all have their 1st operand register being WRITTEN and not READ.
    PATTERNS_IMM = [
        ("00 00 80 D2", "mov x0, #0"),
        ("E2 66 82 52", "movz w2, #0x1337"),
        ("A3 D5 9B 92", "movn x3, #0xdead"),
        ("E4 DD 97 12", "movn w4, #0xbeef"),
        ("03 40 A0 D2", "mov x3, #0x2000000") # aliased to MOVZXi.
    ]

    PATTERNS_REG = [
        ("00 20 18 D5", "msr ttbr0_el1, x0"),
        ("20 20 38 D5", "mrs x0, ttbr1_el1")
    ]

    def setUp(self):
        self.insts = []
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

        for pattern, asm in self.PATTERNS_IMM:
            l = list(self.cs.disasm(bytes.fromhex(pattern), 0))
            self.assertTrue(len(l) == 1)

            _, expected_reg_written, _ = asm.split()
            # strip comma and [].
            expected_reg_written = [expected_reg_written[:-1]]
            expected_reg_read = [] # nothing should be read.
            expected_regs = [expected_reg_read, expected_reg_written]

            self.insts.append((l[0], asm, expected_regs, False))

        for pattern, asm in self.PATTERNS_REG:
            l = list(self.cs.disasm(bytes.fromhex(pattern), 0))
            self.assertTrue(len(l) == 1)

            _, expected_reg_written, expected_reg_read = asm.split()
            # strip comma and [], only keep general purpose registers.
            expected_reg_written = expected_reg_written[:-1]
            expected_reg_written = [expected_reg_written] if expected_reg_written[0].lower() == 'x' else []
            expected_reg_read = [expected_reg_read] if expected_reg_read[0].lower() == 'x' else []
            expected_regs = [expected_reg_read, expected_reg_written]

            self.insts.append((l[0], asm, expected_regs, True))

    def test_regs_access(self):
        """Check that the `regs_access` API provides correct data"""

        for inst, asm, expected_regs, pattern_reg in self.insts:
            # Check that the instruction writes the first register operand and reads the second.
            for i, decoded_regs in enumerate(map(lambda l: list(map(self.cs.reg_name, l)), inst.regs_access())):
                self.assertEqual(decoded_regs, expected_regs[i], "%s has %r %s registers instead of %r" % (asm, decoded_regs, ["read", "written"][i], expected_regs[i]))

    def test_operands(self):
        """Check that the `operands` API provides correct data"""
        for inst, asm, expected_regs, pattern_reg in self.insts:
            ops = inst.operands
            self.assertEqual(len(ops), 2)

            reg_types = [CS_OP_REG, ARM64_OP_SYS] if pattern_reg else [CS_OP_REG]

            self.assertIn(ops[0].type, reg_types, "%s has operand 0 with invalid type" % asm)
            self.assertEqual(ops[0].access, CS_AC_WRITE, "%s has operand 0 with invalid access" % asm)
            if pattern_reg:
                self.assertIn(ops[1].type, reg_types, "%s has operand 0 with invalid type" % asm)
            else:
                self.assertEqual(ops[1].type, CS_OP_IMM, "%s has operand 0 with invalid type" % asm)

if __name__ == '__main__':
    unittest.main()

