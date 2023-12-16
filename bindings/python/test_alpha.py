#!/usr/bin/env python

# Capstone Python bindings, by Sibirtsev Dmitry <sibirtsev_dl@gmail.com>

from __future__ import print_function
from capstone import *
from capstone.alpha import *
from xprint import to_x, to_hex

ALPHA_CODE = b'\x02\x00\xbb\x27\x50\x7a\xbd\x23\xd0\xff\xde\x23\x00\x00\x5e\xb7'

all_tests = (
    (CS_ARCH_ALPHA, 0, ALPHA_CODE, "Alpha"),
)


def print_insn_detail(insn):
    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = 0
        for i in insn.operands:
            if i.type == ALPHA_OP_REG:
                print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg)))
            if i.type == ALPHA_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%s" % (c, to_x(i.imm)))
            c += 1


# ## Test class Cs
def test_class():
    for (arch, mode, code, comment) in all_tests:
        print("*" * 16)
        print("Platform: %s" % comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True
            for insn in md.disasm(code, 0x1000):
                print_insn_detail(insn)
                print()
                print("0x%x:\n" % (insn.address + insn.size))
        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()
