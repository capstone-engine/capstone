#!/usr/bin/env python3

# Capstone by Nguyen Anh Quynnh <aquynh@gmail.com>
# PPC Branch testing suite by kratolp
from __future__ import print_function
import sys
from capstone import *

CODE32  = b"\x48\x01\x05\x15" # bl .+0x10514
CODE32 += b"\x4B\xff\xff\xfd" # bl .-0x4
CODE32 += b"\x48\x00\x00\x0c" # b .+0xc
CODE32 += b"\x41\x80\xff\xd8" # blt .-0x28
CODE32 += b"\x40\x80\xff\xec" # bge .-0x14
CODE32 += b"\x41\x84\x01\x6c" # blt cr1, .+0x16c
CODE32 += b"\x41\x82\x00\x10" # beq .+0x10
CODE32 += b"\x40\x82\x00\x08" # bne .+0x8
CODE32 += b"\x40\x95\x00\x94" # ble cr5,.+0x94
CODE32 += b"\x40\x9f\x10\x30" # bns cr5,.+0x94
CODE32 += b"\x42\x00\xff\xd8" # bdnz .-0x28
CODE32 += b"\x4d\x82\x00\x20" # beqlr
CODE32 += b"\x4e\x80\x00\x20" # blr
CODE32 += b"\x4a\x00\x00\x02" # ba .0xfe000000
CODE32 += b"\x41\x80\xff\xda" # blta .0xffffffd8
CODE32 += b"\x41\x4f\xff\x17" # bdztla 4*cr3+so, .0xffffff14
CODE32 += b"\x43\x20\x0c\x07" # bdnzla+ .0xc04
CODE32 += b"\x4c\x00\x04\x20" # bdnzfctr lt

_python3 = sys.version_info.major == 3

all_tests = (
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, CODE32, "PPC branch instruction decoding", 0),
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
