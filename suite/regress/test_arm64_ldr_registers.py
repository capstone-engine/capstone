import unittest
from capstone import *
from capstone.arm64 import *

class SubRegTest(unittest.TestCase):

    PATTERNS = [
        ("41 00 40 F9", "ldr x1, [x2]"),
        ("41 00 40 39", "ldrb w1, [x2]"),
        ("41 00 C0 39", "ldrsb w1, [x2]"),
        ("41 00 40 79", "ldrh w1, [x2]"),
        ("88 c2 bf f8", "ldapr x8, [x20]"),
        ]

    def setUp(self):
        self.insts = []
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

        for pattern, asm in self.PATTERNS:
            l = list(self.cs.disasm(bytes.fromhex(pattern), 0))
            self.assertTrue(len(l) == 1)

            _, expected_reg_written, expected_reg_read = asm.split()
            # strip comma and []
            expected_reg_written = expected_reg_written[:-1]
            expected_reg_read = expected_reg_read[1:-1]
            expected_regs = [expected_reg_read, expected_reg_written]

            self.insts.append((l[0], asm, expected_regs))


    def test_registers(self):
        """Check that the `regs_access` API provides correct data"""
        
        for inst, asm, expected_regs in self.insts:

            # Check that the instruction writes the first register operand and reads the second
            for i, decoded_regs in enumerate(map(lambda l: list(map(self.cs.reg_name, l)), inst.regs_access())):
                self.assertEqual(len(decoded_regs), 1, "%s has %d %s registers instead of 1" % (asm, len(decoded_regs), ["read", "written"][i]))
                decoded_reg = decoded_regs[0]
                self.assertEqual(expected_regs[i], decoded_reg, "%s test"%i)

    def test_operands(self):
        """Check that the `operands` API provides correct data"""
        for inst, asm, expected_regs in self.insts:
            ops = inst.operands
            self.assertEqual(len(ops), 2)
            
            self.assertEqual(ops[0].type, CS_OP_REG, "%s has operand 0 with invalid type" % asm)
            self.assertEqual(ops[0].access, CS_AC_WRITE, "%s has operand 0 with invalid access" % asm)
            self.assertEqual(ops[1].type, CS_OP_MEM, "%s has operand 0 with invalid type" % asm)
            self.assertEqual(self.cs.reg_name(ops[1].mem.base), expected_regs[0], "%s has operand 1 with invalid reg" % asm)
            self.assertEqual(ops[1].access, CS_AC_READ, "%s has operand 1 with invalid access" % asm)

if __name__ == '__main__':
    unittest.main()
