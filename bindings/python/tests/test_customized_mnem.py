#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
from capstone.x86 import *
from xprint import to_hex


X86_CODE32 = b"\x75\x01"


def print_insn(md, code):
    print("%s\t" % to_hex(code, False), end="")

    for insn in md.disasm(code, 0x1000):
        print("\t%s\t%s\n" % (insn.mnemonic, insn.op_str))


def test():
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        print("Disassemble X86 code with default instruction mnemonic")
        print_insn(md, X86_CODE32)

        print("Now customize engine to change mnemonic from 'JNE' to 'JNZ'")
        md.mnemonic_setup(X86_INS_JNE, "jnz")
        print_insn(md, X86_CODE32)

        print("Reset engine to use the default mnemonic")
        md.mnemonic_setup(X86_INS_JNE, None)
        print_insn(md, X86_CODE32)
    except CsError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test()
