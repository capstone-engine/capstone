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

CODE32 += b"\x66\x2e\x0f\x58\xc0" # addpd   xmm0, xmm0
CODE32 += b"\x2e\x66\x0f\x58\xc0" # addpd   xmm0, xmm0
CODE32 += b"\x66\xf2\x0f\x38\xf1\xc3" # crc32w %bx, %eax
CODE32 += b"\xf2\x0f\x38\xf1\x8c\xcb\xef\xbe\xad\xde" # crc32l -0x21524111(%ebx, %ecx, 8), %ecx

CODE32_MEMREF  = b"\x8b\x84\x91\x23\x01\x00\x00"
CODE32_MEMREF += b"\x8b\x04\x95\x23\x01\x00\x00"
CODE32_MEMREF += b"\x8b\x04\x95\xdd\xfe\xff\xff"
CODE32_MEMREF += b"\xa1\x23\x01\x00\x00"
CODE32_MEMREF += b"\xa1\x00\x00\x00\x00"
CODE32_MEMREF += b"\xa1\xdd\xfe\xff\xff"
CODE32_MEMREF += b"\x8b\x04\x91"

CODE64_MEMREF  = b"\xa3\x0b\x00\x00\x0f\xbe\xc0\x48\x83"
CODE64_MEMREF += b"\xa0\x71\xfa\xff\x48\x85\xc0\x48\x89"

CODE32_ARITH  = b"\x83\xe0\xf7"
CODE32_ARITH += b"\x83\xe0\x10"
CODE32_ARITH += b"\x83\xe0\x00"
CODE32_ARITH += b"\x80\x23\x10"

CODE64_ARITH  = b"\x41\x83\xe0\xfa"
CODE64_ARITH += b"\x48\x83\xe4\xf0"

CODE32_IMM  = b"\xc2\xb8\xc0"
CODE32_IMM += b"\xc2\x0f\x92"
CODE32_IMM += b"\x02\x2d\x00\x00\x00\x83"



_python3 = sys.version_info.major == 3

all_tests = (
        (CS_ARCH_X86, CS_MODE_32, CODE32, "X86 32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, CODE32, "X86 32 (ATT syntax)", CS_OPT_SYNTAX_ATT),

        (CS_ARCH_X86, CS_MODE_32, CODE32_MEMREF, "X86 32 MemRef (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, CODE32_MEMREF, "X86 32 MemRef (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_64, CODE64_MEMREF, "X86 64 (Intel syntax)", 0),

        (CS_ARCH_X86, CS_MODE_32, CODE32_ARITH, "X86 32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_64, CODE64_ARITH, "X86 64 (Intel syntax)", 0),

        (CS_ARCH_X86, CS_MODE_32, CODE32_IMM, "X86 32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, CODE32_IMM, "X86 32 (Intel syntax)", CS_OPT_SYNTAX_ATT),
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
        md = Cs(arch, mode)
        if syntax != 0:
            md.syntax = syntax
        for insn in md.disasm(code, 0x1000):
            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        print("--------")


if __name__ == '__main__':
    test_cs_disasm_quick()
