import unittest
from capstone import *
from capstone.riscv import *
import unittest

class TestRiscvRegAccess(unittest.TestCase):
    def setUp(self):
        self.cs = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        self.cs.option(CS_OPT_DETAIL, CS_OPT_DETAIL_REAL | CS_OPT_ON)

    def test_addi(self):
        # addi a0, a1, 10
        code = b"\x13\x85\xa5\x00"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        # a1 = RISCV_REG_X11, a0 = RISCV_REG_X10
        self.assertIn(RISCV_REG_X11, read)
        self.assertIn(RISCV_REG_X10, write)
        self.assertEqual(len(read), 1)
        self.assertEqual(len(write), 1)

    def test_jalr(self):
        # jalr ra, a1, 0 -> 0x000580e7 (rd=x1=ra, rs1=x11=a1, imm=0)
        code = b"\xe7\x80\x05\x00"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        # ra = RISCV_REG_X1
        self.assertIn(RISCV_REG_X11, read)
        self.assertIn(RISCV_REG_X1, write)
        self.assertEqual(len(read), 1)
        self.assertEqual(len(write), 1)

    def test_lb(self):
        # lb a0, 0(sp)
        code = b"\x03\x05\x01\x00"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        # sp = RISCV_REG_X2
        self.assertIn(RISCV_REG_X2, read)
        self.assertIn(RISCV_REG_X10, write)
        self.assertEqual(len(read), 1)
        self.assertEqual(len(write), 1)

    def test_caddi(self):
        # c.addi a0, 10 (0x0529)
        code = b"\x29\x05"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        # x10 is both read and written
        self.assertIn(RISCV_REG_X10, read)
        self.assertIn(RISCV_REG_X10, write)
        self.assertEqual(len(read), 1)
        self.assertEqual(len(write), 1)

    def test_ecall(self):
        # ecall
        code = b"\x73\x00\x00\x00"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        self.assertEqual(len(read), 0)
        self.assertEqual(len(write), 0)

    def test_csrrw(self):
        # csrrw a0, sstatus, a1
        code = b"\x73\x95\x05\x10"
        insns = list(self.cs.disasm(code, 0))
        self.assertEqual(len(insns), 1)
        insn = insns[0]
        
        read, write = insn.regs_access()
        # CSRs should NOT be in the reg_access list
        self.assertIn(RISCV_REG_X11, read)
        self.assertIn(RISCV_REG_X10, write)
        self.assertEqual(len(read), 1)
        self.assertEqual(len(write), 1)

def test():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestRiscvRegAccess)
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite).failures 
    
def main():
    unittest.main()
    
if __name__ == '__main__':
    main()
