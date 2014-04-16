#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
import sys
from capstone import *

CODE32  = b"\xc0\xe0\x02"
CODE32 += b"\xc0\xf0\x02"
CODE32 += b"\xc1\xf6\x00"

_python3 = sys.version_info.major == 3

all_tests = (
        (CS_ARCH_X86, CS_MODE_32, CODE32, "X86 32 (Intel syntax)", 0),
        #(CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)", 0),
)


def to_hex(s):
    if _python3:
        return " ".join("0x{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        return " ".join("0x{0:02x}".format(ord(c)) for c in s)

# ## Test cs_disasm_quick()
def test_cs_disasm_quick():
    for (arch, mode, code, comment, syntax) in all_tests:
        print("Platform: %s" % comment)
        print("Code: %s" %(to_hex(code))),
        print("Disasm:")
        for (addr, size, mnemonic, op_str) in cs_disasm_lite(arch, mode, code, 0x1000):
            print("0x%x:\t%s\t%s" % (addr, mnemonic, op_str))
        print()


if __name__ == '__main__':
    test_cs_disasm_quick()
