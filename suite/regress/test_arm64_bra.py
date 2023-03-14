import unittest
from capstone import *
from capstone.arm64 import *

class ARM64BRAARegAccessTest(unittest.TestCase):

    # These instructions should all have all their register operands being READ.
    # https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/BRAA--BRAAZ--BRAB--BRABZ--Branch-to-Register--with-pointer-authentication-
    PATTERNS = [
        ("5F 08 1F D6", "braaz x2"),
        ("11 0A 1F D7", "braa x16, x17"),
        ("1F 0C 1F D6", "brabz x0"),
        ("11 0E 1F D7", "brab x16, x17"),
        ]

    def setUp(self):
        self.insts = []
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

        for pattern, asm in self.PATTERNS:
            # Disassemble the instruction. Any error here means Capstone doesn't handle the instruction (maybe the wrong branch)
            inst = next(self.cs.disasm(bytes.fromhex(pattern), 0))

            expected_regs_read = list(map(lambda r: r.strip(', '), asm.split()[1:]))
            expected_regs_written = [] # nothing written
            expected_regs = [expected_regs_read, expected_regs_written]

            self.insts.append((inst, asm, expected_regs))


    def test_regs_access(self):
        """Check that the `regs_access` API provides correct data"""
        
        for inst, asm, expected_regs in self.insts:

            # Check that the instruction writes the first register operand and reads the second
            for i, decoded_regs in enumerate(map(lambda l: list(map(self.cs.reg_name, l)), inst.regs_access())):
                self.assertEqual(decoded_regs, expected_regs[i], "%s has %r %s registers instead of %r" % (asm, decoded_regs, ["read", "written"][i], expected_regs[i]))


    def test_operands(self):
        """Check that the `operands` API provides correct data"""
        for inst, asm, expected_regs in self.insts:
            ops = inst.operands

            expected_regs_read, expected_regs_written = expected_regs
            self.assertEqual(len(expected_regs_written), 0)
            #print("Ensuring %s has the following read registers: %r" % (asm, expected_regs_read))
            self.assertEqual(len(ops), len(expected_regs_read))
            
            for i, op in enumerate(ops):
                self.assertEqual(op.type, CS_OP_REG, "%s has operand %d with invalid type" % (asm, i))
                self.assertEqual(op.access, CS_AC_READ, "%s has operand %d with invalid access" % (asm, i))
            
if __name__ == '__main__':
    unittest.main()
