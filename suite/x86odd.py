#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
import sys
from capstone import *

CODE32  = b"\xc0\xe0\x02"
CODE32 += b"\xc0\xf6\x02"              # sal dh, 0
CODE32 += b"\xc1\xf6\x00"              # sal esi, 0
CODE32 += b"\x82\xc0\x00"
CODE32 += b"\x0f\x1a\x00"              # nop dword ptr [eax]
CODE32 += b"\xf7\xc0\x11\x22\x33\x44"  # test eax, 0x44332211
CODE32 += b"\xf7\xc8\x11\x22\x33\x44"  # test eax, 0x44332211
CODE32 += b"\xf7\x88\x00\x00\x00\x00\x00\x00\x00\x00"  # test dword ptr [eax], 0
CODE32 += b"\xf6\x88\x00\x00\x00\x00\x00"              # test byte ptr [eax], 0

CODE32 += b"\xd9\xd8"       # fstpnce st(0), st(0)
CODE32 += b"\xdf\xdf"       # fstp    st(7), st(0)

CODE32 += b"\x0f\x20\x00"       # mov eax, cr0
CODE32 += b"\x0f\x20\x40"       # mov eax, cr0
CODE32 += b"\x0f\x20\x80"       # mov eax, cr0

CODE32 += b"\x0f\x22\x00"       # mov cr0, eax
CODE32 += b"\x0f\x22\x40"       # mov cr0, eax
CODE32 += b"\x0f\x22\x80"       # mov cr0, eax

CODE32 += b"\x0f\x21\x00"       # mov eax, dr0
CODE32 += b"\x0f\x21\x40"       # mov eax, dr0
CODE32 += b"\x0f\x21\x80"       # mov eax, dr0

CODE32 += b"\x0f\x23\x00"       # mov dr0, eax
CODE32 += b"\x0f\x23\x40"       # mov dr0, eax
CODE32 += b"\x0f\x23\x80"       # mov dr0, eax


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
