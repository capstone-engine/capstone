import unittest
from capstone import *
from capstone.arm64 import *

class ARM64AtomicsRegAccessTest(unittest.TestCase):

    # https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions
    INSTRUCTIONS = [
        ("41 80 20 b8", "swp w0, w1, [x2]",       {"w0", "x2"},       {"w1"}),
        ("41 80 a0 b8", "swpa w0, w1, [x2]",      {"w0", "x2"},       {"w1"}),
        ("41 7c a0 88", "cas w0, w1, [x2]",       {"w0", "w1", "x2"}, {"w0"}),
        ("82 7c 20 48", "casp x0, x1, x2, x3, [x4]",
                                                  {"x0", "x1", "x2", "x3", "x4"}, {"x0", "x1"}),
        ("82 fc 60 48", "caspal x0, x1, x2, x3, [x4]",
                                                  {"x0", "x1", "x2", "x3", "x4"}, {"x0", "x1"}),
        ("41 00 20 b8", "ldadd w0, w1, [x2]",     {"w0", "x2"},       {"w1"}),
        ("41 00 e0 f8", "ldaddal x0, x1, [x2]",   {"x0", "x2"},       {"x1"}),
        ("41 10 20 b8", "ldclr w0, w1, [x2]",     {"w0", "x2"},       {"w1"}),
        ]

    def setUp(self):
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

    def test_regs_access(self):
        """Check that the `regs_access` API reports the atomic value/destination registers"""
        for encoding, asm, expected_read, expected_written in self.INSTRUCTIONS:
            inst = next(self.cs.disasm(bytes.fromhex(encoding.replace(" ", "")), 0))

            regs_read, regs_written = inst.regs_access()
            read = set(map(self.cs.reg_name, regs_read))
            written = set(map(self.cs.reg_name, regs_written))

            self.assertEqual(read, expected_read,
                             "%s reads %r instead of %r" % (asm, read, expected_read))
            self.assertEqual(written, expected_written,
                             "%s writes %r instead of %r" % (asm, written, expected_written))


if __name__ == '__main__':
    unittest.main()
