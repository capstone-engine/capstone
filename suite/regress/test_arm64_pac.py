import unittest
from capstone import *
from capstone.arm64 import *
from collections import defaultdict

class ARM64PACRegAccessTest(unittest.TestCase):

    PATTERNS = [
        ("41 00 C1 DA", "pacia x1, x2"),
        ("3F 23 03 D5", "paciasp"),
        ("E1 23 C1 DA", "paciza x1"),
        ("41 04 C1 DA", "pacib x1, x2"),
        ("7F 23 03 D5", "pacibsp"),
        ("E1 27 C1 DA", "pacizb x1"),
        ("41 08 C1 DA", "pacda x1, x2"),
        ("E1 2B C1 DA", "pacdza x1"),
        ("41 0C C1 DA", "pacdb x1, x2"),
        ("E1 2F C1 DA", "pacdzb x1"),
        ("41 18 C1 DA", "autda x1, x2"),
        ("E1 3B C1 DA", "autdza x1"),
        ("41 1C C1 DA", "autdb x1, x2"),
        ("E1 3F C1 DA", "autdzb x1"),
        ("41 10 C1 DA", "autia x1, x2"),
        ("BF 23 03 D5", "autiasp"),
        ("E1 33 C1 DA", "autiza x1"),
        ("9F 23 03 D5", "autiaz"),
        ("41 14 C1 DA", "autib x1, x2"),
        ("FF 23 03 D5", "autibsp"),
        ("E1 37 C1 DA", "autizb x1"),
        ("DF 23 03 D5", "autibz"),
        ("E1 47 C1 DA", "xpacd x1"),
        ("E1 43 C1 DA", "xpaci x1"),
        ("FF 20 03 D5", "xpaclri"),
        ]

    def setUp(self):
        self.insts = []
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

        for pattern, asm in self.PATTERNS:
            # Disassemble the instruction. Any error here means Capstone doesn't handle the instruction (maybe the wrong branch)
            inst = next(self.cs.disasm(bytes.fromhex(pattern), 0))

            # Build the lists of expected read and written registers
            regs = list(map(lambda r: r.strip(', '), asm.split()[1:]))
            expected_regs_read = []
            n = len(regs)
            if(n == 0):
                expected_regs_written = ["lr"]
                expected_regs_read = ["lr"]
                if(asm.endswith("sp")):
                    expected_regs_read += ["sp"]
            elif(n == 1):
                expected_regs_written = [regs[0]]
                expected_regs_read = [regs[0]]
            elif(n == 2):
                expected_regs_written = [regs[0]]
                expected_regs_read = regs
            
            expected_regs = [expected_regs_read, expected_regs_written]
            #print((inst, asm, expected_regs))

            self.insts.append((inst, asm, expected_regs))


    def test_regs_access(self):
        """Check that the `regs_access` API provides correct data"""
        
        for inst, asm, expected_regs in self.insts:
            for i, decoded_regs in enumerate(map(lambda l: list(map(self.cs.reg_name, l)), inst.regs_access())):
                self.assertEqual(set(decoded_regs), set(expected_regs[i]), "%s has %r %s registers instead of %r" % (asm, decoded_regs, ["read", "written"][i], expected_regs[i]))


    def test_operands(self):
        """Check that the `operands` API provides correct data"""
        for inst, asm, expected_regs in self.insts:
            ops = inst.operands
            asm_regs = list(map(lambda r: r.strip(', '), asm.split()[1:]))
            self.assertEqual(len(ops), len(asm_regs))

            expected_regs_accesses = defaultdict(int)
            
            expected_regs_read, expected_regs_written = expected_regs
            for reg in expected_regs_written:
                expected_regs_accesses[reg] |= CS_AC_WRITE
            for reg in expected_regs_read:
                expected_regs_accesses[reg] |= CS_AC_READ
            
            for i, op in enumerate(ops):
                self.assertEqual(op.type, CS_OP_REG, "%s has operand %d with invalid type" % (asm, i))
                regname = self.cs.reg_name(op.reg)
                self.assertEqual(op.access, expected_regs_accesses[regname], "%s has operand %d (%s) with invalid access (%d != %d)" % (asm, i, regname, op.access, expected_regs_accesses[regname]))

            
if __name__ == '__main__':
    unittest.main()
