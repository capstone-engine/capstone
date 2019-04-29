#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
from capstone.riscv import *
from xprint import to_x, to_hex

RISCV_CODE32 = b"\x37\x34\x00\x00\x97\x82\x00\x00\xef\x00\x80\x00\xef\xf0\x1f\xff\xe7\x00\x45\x00\xe7\x00\xc0\xff\x63\x05\x41\x00\xe3\x9d\x61\xfe\x63\xca\x93\x00\x63\x53\xb5\x00\x63\x65\xd6\x00\x63\x76\xf7\x00\x03\x88\x18\x00\x03\x99\x49\x00\x03\xaa\x6a\x00\x03\xcb\x2b\x01\x03\xdc\x8c\x01\x23\x86\xad\x03\x23\x9a\xce\x03\x23\x8f\xef\x01\x93\x00\xe0\x00\x13\xa1\x01\x01\x13\xb2\x02\x7d\x13\xc3\x03\xdd\x13\xe4\xc4\x12\x13\xf5\x85\x0c\x13\x96\xe6\x01\x13\xd7\x97\x01\x13\xd8\xf8\x40\x33\x89\x49\x01\xb3\x0a\x7b\x41\x33\xac\xac\x01\xb3\x3d\xde\x01\x33\xd2\x62\x40\xb3\x43\x94\x00\x33\xe5\xc5\x00\xb3\x76\xf7\x00\xb3\x54\x39\x01\xb3\x50\x31\x00\x33\x9f\x0f\x00"
RISCV_CODE64 = b"\x13\x04\xa8\x7a"

all_tests = (
        (CS_ARCH_RISCV, CS_MODE_RISCV32, RISCV_CODE32, "riscv32"),
        (CS_ARCH_RISCV, CS_MODE_RISCV64, RISCV_CODE64, "riscv64"),
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
            if i.type == RISCV_OP_REG:
                print("\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg)))
            if i.type == RISCV_OP_IMM:
                print("\t\toperands[%u].type: IMM = 0x%s" % (c, to_x(i.imm)))
            if i.type == RISCV_OP_MEM:
                print("\t\toperands[%u].type: MEM" % c)
                if i.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" \
                        % (c, insn.reg_name(i.mem.base)))
                if i.mem.disp != 0:
                    print("\t\t\toperands[%u].mem.disp: 0x%s" \
                        % (c, to_x(i.mem.disp)))
            c += 1


# ## Test class Cs
def test_class():

    for (arch, mode, code, comment) in all_tests:
        print("*" * 16)
        print("Platform: %s" %comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True
            for insn in md.disasm(code, 0x1000):
                print_insn_detail(insn)
                print ()
            print("0x%x:\n" % (insn.address + insn.size))
        except CsError as e:
            print("ERROR: %s" %e)


if __name__ == '__main__':
    test_class()