#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
from capstone.arm64 import *

ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

all_tests = (
        (CS_ARCH_ARM64, CS_MODE_ARM, ARM64_CODE, "ARM-64"),
        )

def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s).encode('hex')
    while x[0] == '0': x = x[1:]
    return x

### Test class Cs
def test_class():
    def print_insn_detail(insn):
        # print address, mnemonic and operands
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            print("\top_count: %u" %len(insn.operands))
            c = -1
            for i in insn.operands:
                c += 1
                if i.type == ARM64_OP_REG:
                    print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.reg)))
                if i.type == ARM64_OP_IMM:
                    print("\t\toperands[%u].type: IMM = 0x%s" %(c, to_x(i.imm)))
                if i.type == ARM64_OP_CIMM:
                    print("\t\toperands[%u].type: C-IMM = %u" %(c, i.imm))
                if i.type == ARM64_OP_FP:
                    print("\t\toperands[%u].type: FP = %f" %(c, i.fp))
                if i.type == ARM64_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" \
                            %(c, insn.reg_name(i.mem.base)))
                    if i.mem.index != 0:
                        print("\t\t\toperands[%u].mem.index: REG = %s" \
                            %(c, insn.reg_name(i.mem.index)))
                    if i.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: 0x%s" \
                            %(c, to_x(i.mem.disp)))

                if i.shift.type != ARM64_SFT_INVALID and i.shift.value:
		            print("\t\t\tShift: type = %u, value = %u" \
                        %(i.shift.type, i.shift.value))

                if i.ext != ARM64_EXT_INVALID:
		            print("\t\t\tExt: %u" %i.ext)

        if insn.writeback:
            print("\tWrite-back: True")
        if not insn.cc in [ARM64_CC_AL, ARM64_CC_INVALID]:
            print("\tCode condition: %u" %insn.cc)
        if insn.update_flags:
            print("\tUpdate-flags: True")

    for (arch, mode, code, comment) in all_tests:
        print("*" * 16)
        print("Platform: %s" %comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True
            for insn in md.disasm(code, 0x2c):
                print_insn_detail(insn)
                print
            print "0x%x:\n" % (insn.address + insn.size)
        except CsError as e:
            print("ERROR: %s" %e)


test_class()
