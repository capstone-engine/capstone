#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
from capstone.systemz import *

SYSZ_CODE = "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"
all_tests = (
        (CS_ARCH_SYSZ, 0, SYSZ_CODE, "SystemZ"),
        )

def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s).encode('hex')
    while x[0] == '0': x = x[1:]
    return x

def to_x_32(s):
    from struct import pack
    if not s: return '0'
    x = pack(">i", s).encode('hex')
    while x[0] == '0': x = x[1:]
    return x

### Test class Cs
def test_class():
    def print_insn_detail(insn):
        # print address, mnemonic and operands
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            print("\top_count: %u" %len(insn.operands))
            c = 0
            for i in insn.operands:
                if i.type == SYSZ_OP_REG:
                    print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.reg)))
                if i.type == SYSZ_OP_ACREG:
                    print("\t\toperands[%u].type: ACREG = %u" %(c, i.reg))
                if i.type == SYSZ_OP_IMM:
                    print("\t\toperands[%u].type: IMM = 0x%s" %(c, to_x_32(i.imm)))
                if i.type == SYSZ_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" \
                            %(c, insn.reg_name(i.mem.base)))
                    if i.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: 0x%s" \
                            %(c, to_x_32(i.mem.disp)))
                c += 1

        if insn.cc:
            print("\tConditional code: %u" %insn.cc)

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
                print
            print "0x%x:\n" % (insn.address + insn.size)
        except CsError as e:
            print("ERROR: %s" %e)


test_class()
